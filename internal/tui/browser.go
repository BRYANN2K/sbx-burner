package tui

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// browser is a plain file browser: folders end with "/", no icons.
type browser struct {
	dir     string
	entries []entry
	cursor  int
	dirs    bool // folders may be picked
	files   bool // files may be picked
	types   []string
	hidden  bool // show dot files
	err     string
}

type entry struct {
	name string
	dir  bool
}

func newBrowser(start string, dirs, files bool, types []string) *browser {
	b := &browser{dirs: dirs, files: files, types: types}
	if abs, err := filepath.Abs(start); err == nil {
		start = abs
	}
	b.open(start)
	return b
}

func (b *browser) open(dir string) {
	list, err := os.ReadDir(dir)
	if err != nil {
		b.err = "cannot open " + dir
		return
	}
	b.dir, b.err, b.cursor = dir, "", 0
	b.entries = nil
	if parent := filepath.Dir(dir); parent != dir {
		b.entries = append(b.entries, entry{"..", true})
	}
	var ds, fs []entry
	for _, e := range list {
		name := e.Name()
		if strings.HasPrefix(name, ".") && !b.hidden {
			continue
		}
		isDir := e.IsDir()
		if e.Type()&os.ModeSymlink != 0 {
			if st, err := os.Stat(filepath.Join(dir, name)); err == nil {
				isDir = st.IsDir()
			}
		}
		if isDir {
			ds = append(ds, entry{name, true})
		} else if b.files && b.typeOK(name) {
			fs = append(fs, entry{name, false})
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].name < ds[j].name })
	sort.Slice(fs, func(i, j int) bool { return fs[i].name < fs[j].name })
	b.entries = append(append(b.entries, ds...), fs...)
	if len(b.entries) > 1 && b.entries[0].name == ".." {
		b.cursor = 1
	}
}

func (b *browser) typeOK(name string) bool {
	if len(b.types) == 0 {
		return true
	}
	for _, t := range b.types {
		if strings.HasSuffix(strings.ToLower(name), t) {
			return true
		}
	}
	return false
}

func (b *browser) up() {
	if b.cursor > 0 {
		b.cursor--
	}
}

func (b *browser) down() {
	if b.cursor < len(b.entries)-1 {
		b.cursor++
	}
}

func (b *browser) parent() { b.open(filepath.Dir(b.dir)) }

// toggleHidden shows or hides dot files and folders.
func (b *browser) toggleHidden() {
	b.hidden = !b.hidden
	cur := ""
	if b.cursor < len(b.entries) {
		cur = b.entries[b.cursor].name
	}
	b.open(b.dir)
	for i, e := range b.entries {
		if e.name == cur {
			b.cursor = i
		}
	}
}

// enter opens a folder, or picks a file. It returns the picked path.
func (b *browser) enter() (string, bool) {
	if len(b.entries) == 0 {
		return "", false
	}
	e := b.entries[b.cursor]
	p := filepath.Join(b.dir, e.name)
	if e.name == ".." {
		b.parent()
		return "", false
	}
	if e.dir {
		b.open(p)
		return "", false
	}
	return p, true
}

// pick selects the highlighted entry (space): a folder when folders may be
// picked, or a file.
func (b *browser) pick() (string, bool) {
	if len(b.entries) == 0 {
		return "", false
	}
	e := b.entries[b.cursor]
	if e.name == ".." {
		return "", false
	}
	p := filepath.Join(b.dir, e.name)
	if e.dir && b.dirs || !e.dir && b.files {
		return p, true
	}
	return "", false
}

// pickHere selects the open folder (".").
func (b *browser) pickHere() (string, bool) {
	if b.dirs {
		return b.dir, true
	}
	return "", false
}

func (b *browser) view(w, h int) string {
	lines := []string{sDim.Render(truncate(b.dir+"/", w))}
	if b.err != "" {
		lines = append(lines, sAmber.Render(b.err))
	}
	visible := h - 1
	if visible < 3 {
		visible = 3
	}
	start := 0
	if b.cursor >= visible {
		start = b.cursor - visible + 1
	}
	for i := start; i < len(b.entries) && i < start+visible; i++ {
		e := b.entries[i]
		name := e.name
		if e.dir && name != ".." {
			name += "/"
		}
		name = truncate(name, w-4)
		if i == b.cursor {
			lines = append(lines, sel(w, "❯ "+name))
		} else if e.dir {
			lines = append(lines, "  "+sText.Render(name))
		} else {
			lines = append(lines, "  "+sSoft.Render(name))
		}
	}
	if len(b.entries) == 0 {
		lines = append(lines, sDim.Render("  empty"))
	}
	return strings.Join(lines, "\n")
}
