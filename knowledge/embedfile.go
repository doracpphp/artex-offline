package knowledge

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// Precomputed chunk vectors (docs §4.2 "Embedding cost"). Embedding a multi-GB
// corpus on the offline side can take hours, so the builder may embed the
// chunks once, online, and ship the vectors in the pack under embeddings/.
//
// A vector is keyed by the SHA-256 of the exact chunk text, which the builder
// and the importer produce with the same code (documentChunks). So a set is
// usable only with the same chunking budget (ARTEX_KNOWLEDGE_MAX_CHUNK_BYTES)
// and the same embedding model; otherwise it is ignored and the background
// worker embeds as before.
//
// File format (little endian):
//
//	"ARTEX-KV1\n"
//	one JSON line: {"model":…,"dimension":…,"chunk_bytes":…,"count":…}
//	count records: 32-byte SHA-256 of the chunk text, then dimension float32

const embedFileMagic = "ARTEX-KV1\n"

// embedFileHeader is the JSON line after the magic.
type embedFileHeader struct {
	Model      string `json:"model"`
	Dimension  int    `json:"dimension"`
	ChunkBytes int    `json:"chunk_bytes"`
	Count      int    `json:"count"`
}

// chunkHash is the key of a precomputed vector.
func chunkHash(text string) [32]byte { return sha256.Sum256([]byte(text)) }

// embedRecordWriter appends records to a temporary file and, on finish,
// writes the final file: magic, header (now that the count is known), records.
type embedRecordWriter struct {
	tmp   *os.File
	bw    *bufio.Writer
	dim   int
	count int
}

func newEmbedRecordWriter(dir string) (*embedRecordWriter, error) {
	tmp, err := os.CreateTemp(dir, "vectors-*.tmp")
	if err != nil {
		return nil, err
	}
	return &embedRecordWriter{tmp: tmp, bw: bufio.NewWriterSize(tmp, 1<<20)}, nil
}

func (w *embedRecordWriter) add(h [32]byte, vec []float32) error {
	if w.dim == 0 {
		w.dim = len(vec)
	}
	if len(vec) != w.dim || w.dim == 0 {
		return fmt.Errorf("embedding model returned a %d-dimensional vector, expected %d", len(vec), w.dim)
	}
	if _, err := w.bw.Write(h[:]); err != nil {
		return err
	}
	var b [4]byte
	for _, f := range vec {
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(f))
		if _, err := w.bw.Write(b[:]); err != nil {
			return err
		}
	}
	w.count++
	return nil
}

// finish writes the vector file to out and removes the temporary file.
func (w *embedRecordWriter) finish(out string, model string, chunkBytes int) (EmbeddingSet, error) {
	defer os.Remove(w.tmp.Name())
	defer w.tmp.Close()
	if err := w.bw.Flush(); err != nil {
		return EmbeddingSet{}, err
	}
	if _, err := w.tmp.Seek(0, io.SeekStart); err != nil {
		return EmbeddingSet{}, err
	}
	dim := w.dim
	if dim == 0 {
		dim = 1 // an empty set still needs a valid header; it is not declared (see BuildEmbeddings)
	}
	hdr, err := json.Marshal(embedFileHeader{Model: model, Dimension: dim, ChunkBytes: chunkBytes, Count: w.count})
	if err != nil {
		return EmbeddingSet{}, err
	}
	f, err := os.Create(out)
	if err != nil {
		return EmbeddingSet{}, err
	}
	bw := bufio.NewWriter(f)
	bw.WriteString(embedFileMagic)
	bw.Write(hdr)
	bw.WriteByte('\n')
	if _, err := io.Copy(bw, w.tmp); err != nil {
		f.Close()
		return EmbeddingSet{}, err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return EmbeddingSet{}, err
	}
	if err := f.Close(); err != nil {
		return EmbeddingSet{}, err
	}
	return EmbeddingSet{Model: model, Dimension: dim, ChunkBytes: chunkBytes, Count: w.count}, nil
}

// readEmbedFile streams a vector file, checking it against want (the manifest's
// declaration) when want.Model is set. fn gets every record; the vector slice is
// reused between calls.
func readEmbedFile(r io.Reader, want EmbeddingSet, fn func(h [32]byte, vec []float32) error) (embedFileHeader, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	magic := make([]byte, len(embedFileMagic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != embedFileMagic {
		return embedFileHeader{}, fmt.Errorf("not an ARTEX vector file")
	}
	line, err := br.ReadBytes('\n')
	if err != nil || len(line) > 4096 {
		return embedFileHeader{}, fmt.Errorf("vector file header is missing or too long")
	}
	var h embedFileHeader
	if err := json.Unmarshal(line, &h); err != nil {
		return embedFileHeader{}, fmt.Errorf("vector file header: %w", err)
	}
	if h.Dimension < 1 || h.Dimension > maxEmbeddingDim || h.Count < 0 {
		return embedFileHeader{}, fmt.Errorf("vector file header has dimension %d, count %d", h.Dimension, h.Count)
	}
	if want.Model != "" && (h.Model != want.Model || h.Dimension != want.Dimension || h.ChunkBytes != want.ChunkBytes || h.Count != want.Count) {
		return embedFileHeader{}, fmt.Errorf("vector file header %+v does not match the manifest's declaration", h)
	}
	rec := make([]byte, 32+4*h.Dimension)
	vec := make([]float32, h.Dimension)
	for i := 0; i < h.Count; i++ {
		if _, err := io.ReadFull(br, rec); err != nil {
			return h, fmt.Errorf("vector file ended after %d of %d records", i, h.Count)
		}
		var hash [32]byte
		copy(hash[:], rec[:32])
		for j := range vec {
			vec[j] = math.Float32frombits(binary.LittleEndian.Uint32(rec[32+4*j:]))
		}
		if err := fn(hash, vec); err != nil {
			return h, err
		}
	}
	if _, err := br.ReadByte(); err != io.EOF {
		return h, fmt.Errorf("vector file has data after its %d records", h.Count)
	}
	return h, nil
}

// chunkCollector is the builder's docSink: it hands every chunk text of every
// document to fn, exactly as the importer would store it.
type chunkCollector struct {
	maxBytes int
	fn       func(text string) error
}

func (c *chunkCollector) addDocument(_, _, _, title string, _, _ []string, _ any, body string) (int64, error) {
	for _, ch := range documentChunks(title, body, c.maxBytes) {
		if err := c.fn(ch.Text); err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func (c *chunkCollector) addCPEMatch(int64, CPEMatch) error { return nil }

// EmbedBuild configures BuildEmbeddings.
type EmbedBuild struct {
	Files      map[string]string // the FULL pack input (pack path -> source file)
	ChunkBytes int               // the importer's ARTEX_KNOWLEDGE_MAX_CHUNK_BYTES the vectors are for
	Embedder   Embedder
	Digest     string // optional model digest, recorded for information
	// BasePack is an optional previous full pack: its vectors for chunks that
	// are still present are reused instead of embedded again.
	BasePack string
	FullOut  string // vector file covering every chunk, for the full pack
	// DeltaOut, optional, receives only the vectors not already in BasePack,
	// for a delta pack against it.
	DeltaOut string
	// Batch is the number of chunks per embedding request (default 64).
	Batch int
	// Progress, optional, is called after each batch with the vectors written.
	Progress func(done int)
}

// BuildEmbeddings embeds every distinct chunk of a pack input and writes the
// vector file(s). It returns the sets to declare in the manifest (Path left
// empty for the caller); a set with Count 0 should not be declared.
func BuildEmbeddings(ctx context.Context, b EmbedBuild) (full, delta EmbeddingSet, err error) {
	if b.Embedder == nil || b.FullOut == "" {
		return full, delta, errors.New("an embedder and an output file are required")
	}
	if b.Batch <= 0 {
		b.Batch = embedBatch
	}
	view := viewOfFiles(b.Files)
	model := b.Embedder.Model()

	// Pass 1: the distinct chunk hashes of this input.
	present := map[[32]byte]bool{}
	if _, err := indexPack(&chunkCollector{maxBytes: b.ChunkBytes, fn: func(t string) error {
		present[chunkHash(t)] = true
		return nil
	}}, view); err != nil {
		return full, delta, err
	}

	tmpDir := filepath.Dir(b.FullOut)
	fw, err := newEmbedRecordWriter(tmpDir)
	if err != nil {
		return full, delta, err
	}
	var dw *embedRecordWriter
	if b.DeltaOut != "" {
		if dw, err = newEmbedRecordWriter(tmpDir); err != nil {
			return full, delta, err
		}
	}

	// Reuse the base pack's vectors for chunks still present.
	done := map[[32]byte]bool{}
	if b.BasePack != "" {
		if err := basePackVectors(b.BasePack, model, b.ChunkBytes, func(h [32]byte, vec []float32) error {
			if !present[h] || done[h] {
				return nil
			}
			done[h] = true
			return fw.add(h, vec)
		}); err != nil {
			return full, delta, fmt.Errorf("reuse vectors of %s: %w", b.BasePack, err)
		}
	}

	// Pass 2: embed what is left, in batches.
	var texts []string
	var hashes [][32]byte
	flush := func() error {
		if len(texts) == 0 {
			return nil
		}
		vecs, err := b.Embedder.Embed(ctx, texts)
		if err != nil {
			return err
		}
		if len(vecs) != len(texts) {
			return fmt.Errorf("embedding model returned %d vectors for %d texts", len(vecs), len(texts))
		}
		for i, v := range vecs {
			if err := fw.add(hashes[i], v); err != nil {
				return err
			}
			if dw != nil {
				if err := dw.add(hashes[i], v); err != nil {
					return err
				}
			}
		}
		texts, hashes = texts[:0], hashes[:0]
		if b.Progress != nil {
			b.Progress(fw.count)
		}
		return nil
	}
	if _, err := indexPack(&chunkCollector{maxBytes: b.ChunkBytes, fn: func(t string) error {
		h := chunkHash(t)
		if done[h] {
			return nil
		}
		done[h] = true
		texts, hashes = append(texts, t), append(hashes, h)
		if len(texts) >= b.Batch {
			return flush()
		}
		return nil
	}}, view); err != nil {
		return full, delta, err
	}
	if err := flush(); err != nil {
		return full, delta, err
	}
	if full, err = fw.finish(b.FullOut, model, b.ChunkBytes); err != nil {
		return full, delta, err
	}
	full.Digest = b.Digest
	if dw != nil {
		if dw.dim == 0 {
			dw.dim = fw.dim
		}
		if delta, err = dw.finish(b.DeltaOut, model, b.ChunkBytes); err != nil {
			return full, delta, err
		}
		delta.Digest = b.Digest
	}
	return full, delta, nil
}

// basePackVectors streams the vectors of a pack file's embedding sets that
// match model and chunkBytes. The pack is the builder's own previous output; its
// manifest is parsed without a signature check (PackManifest).
func basePackVectors(packPath, model string, chunkBytes int, fn func(h [32]byte, vec []float32) error) error {
	m, err := PackManifest(packPath)
	if err != nil {
		return err
	}
	sets := map[string]EmbeddingSet{}
	for _, e := range m.Embeddings {
		if e.Model == model && e.ChunkBytes == chunkBytes {
			sets[e.Path] = e
		}
	}
	if len(sets) == 0 {
		return nil
	}
	f, err := os.Open(packPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if set, ok := sets[h.Name]; ok {
			if _, err := readEmbedFile(tr, set, fn); err != nil {
				return fmt.Errorf("%s: %w", h.Name, err)
			}
		}
	}
}

// applyPrecomputed inserts the precomputed vectors of every active pack whose
// sets match the configured model and chunking, for chunks that have no vector
// yet. It returns how many chunks got one. Run by the embedding worker before
// it embeds, so only what the pack did not cover is sent to the model.
func (s *Store) applyPrecomputed(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, pack_id, dir, manifest_sha256 FROM kb_packs WHERE active AND dir <> ''`)
	if err != nil {
		return 0, err
	}
	type packRef struct {
		pk               int64
		packID, dir, sha string
	}
	var packs []packRef
	for rows.Next() {
		var p packRef
		if err := rows.Scan(&p.pk, &p.packID, &p.dir, &p.sha); err != nil {
			rows.Close()
			return 0, err
		}
		packs = append(packs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	model := s.embedder.Model()
	total := 0
	for _, p := range packs {
		dir, err := s.cfg.packFilesDir(p.dir)
		if err != nil {
			return total, err
		}
		m, err := readStoredManifest(dir, p.sha)
		if err != nil {
			// A pack imported before vectors were stored has no manifest.json.
			log.Printf("[knowledge] precomputed vectors of %s not used: %v", p.packID, err)
			continue
		}
		var sets []EmbeddingSet
		for _, e := range m.Embeddings {
			if e.Model == model && e.ChunkBytes == s.cfg.MaxChunkBytes && e.Count > 0 {
				sets = append(sets, e)
			}
		}
		if len(sets) == 0 {
			if len(m.Embeddings) > 0 {
				log.Printf("[knowledge] %s ships precomputed vectors, but none for model %s at %d-byte chunks; embedding locally", p.packID, model, s.cfg.MaxChunkBytes)
			}
			continue
		}
		n, err := s.applySets(ctx, p.pk, dir, sets)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// applySets inserts the vectors of sets (all of one model) for the pack row
// pk's chunks that have none.
func (s *Store) applySets(ctx context.Context, pk int64, dir string, sets []EmbeddingSet) (int, error) {
	hasTable, err := tableExists(ctx, s.db, "kb_embeddings")
	if err != nil {
		return 0, err
	}
	q := `SELECT c.id, c.body FROM kb_chunks c JOIN kb_documents d ON d.id = c.document_id WHERE d.pack_id = $1`
	if hasTable {
		q += ` AND NOT EXISTS (SELECT 1 FROM kb_embeddings e WHERE e.chunk_id = c.id)`
	}
	rows, err := s.db.QueryContext(ctx, q, pk)
	if err != nil {
		return 0, err
	}
	want := map[[32]byte][]int64{}
	for rows.Next() {
		var id int64
		var body string
		if err := rows.Scan(&id, &body); err != nil {
			rows.Close()
			return 0, err
		}
		h := chunkHash(body)
		want[h] = append(want[h], id)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(want) == 0 {
		return 0, err
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	applied, schemaReady := 0, false
	var ids []int64
	var vecs [][]float32
	dim := sets[0].Dimension
	flush := func() error {
		if len(ids) == 0 {
			return nil
		}
		if !schemaReady {
			if err := ensureVectorSchema(ctx, s.db, dim, s.embedder.Model()); err != nil {
				return err
			}
			s.vecMu.Lock()
			s.vecReady, s.vecOnce, s.vecDim = true, true, dim
			s.vecMu.Unlock()
			schemaReady = true
		}
		n, err := s.insertEmbeddings(ctx, ids, vecs, dim)
		applied += n
		ids, vecs = ids[:0], vecs[:0]
		return err
	}
	for _, set := range sets {
		if set.Dimension != dim {
			return applied, fmt.Errorf("precomputed sets of model %s disagree on the dimension (%d vs %d)", set.Model, set.Dimension, dim)
		}
		clean, err := SafePath(set.Path)
		if err != nil {
			return applied, err
		}
		f, err := root.Open(filepath.FromSlash(clean))
		if err != nil {
			return applied, err
		}
		_, err = readEmbedFile(f, set, func(h [32]byte, vec []float32) error {
			chunkIDs, ok := want[h]
			if !ok {
				return nil
			}
			delete(want, h) // each chunk once, even if several sets carry it
			for _, id := range chunkIDs {
				ids = append(ids, id)
				vecs = append(vecs, append([]float32(nil), vec...))
			}
			if len(ids) >= 512 {
				return flush()
			}
			return nil
		})
		f.Close()
		if err != nil {
			return applied, fmt.Errorf("%s: %w", clean, err)
		}
	}
	return applied, flush()
}

// carryOverEmbeddings copies, right after a new version of packID became
// active, the current model's vectors of the previous version's chunks to the
// new version's chunks with the same text, so an update re-embeds only what
// changed. It returns how many chunks got a vector; errors are logged (the
// worker then embeds those chunks instead).
func (s *Store) carryOverEmbeddings(ctx context.Context, packID string) int {
	if s.embedder == nil {
		return 0
	}
	if ok, err := tableExists(ctx, s.db, "kb_embeddings"); err != nil || !ok {
		return 0
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO kb_embeddings(chunk_id, model, embedding)
SELECT DISTINCT ON (n.id) n.id, e.model, e.embedding
FROM kb_packs np
JOIN kb_documents nd ON nd.pack_id = np.id
JOIN kb_chunks n ON n.document_id = nd.id
JOIN kb_chunks o ON md5(o.body) = md5(n.body) AND o.body = n.body
JOIN kb_embeddings e ON e.chunk_id = o.id AND e.model = $2
JOIN kb_documents od ON od.id = o.document_id
JOIN kb_packs op ON op.id = od.pack_id AND op.pack_id = $1 AND NOT op.active
WHERE np.pack_id = $1 AND np.active
ON CONFLICT (chunk_id) DO NOTHING`, packID, s.embedder.Model())
	if err != nil {
		log.Printf("[knowledge] reuse vectors of the previous %s version: %v (they are embedded again)", packID, err)
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// embeddingFileName is the pack path the builder gives a vector file: one per
// model and version, so a delta's file never replaces its base's.
func embeddingFileName(model, version string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(model) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return embeddingsPrefix + b.String() + "-" + version + ".akv"
}

// EmbeddingFileName is embeddingFileName for the builder.
func EmbeddingFileName(model, version string) string { return embeddingFileName(model, version) }
