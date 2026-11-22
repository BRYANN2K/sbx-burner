package series

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/BRYANN2K/sbx-burner/internal/catalog"
	"github.com/BRYANN2K/sbx-burner/internal/engine"
)

// TargetKind names the kind of target set in o.
func TargetKind(o engine.RunOptions) string {
	switch {
	case o.TargetURL != "":
		return "url"
	case o.TargetApp != "":
		return "app"
	case o.TargetImage != "":
		return "image"
	case o.TargetRepo != "":
		return "repo"
	case o.Target != "":
		return "path"
	}
	return ""
}

// RunFunc runs one recipe and returns its report path (empty when none),
// the exit code and an error.
type RunFunc func(ctx context.Context, o engine.RunOptions) (report string, code int, err error)

// Plan is what Run will do for each item: the run options, or why it is
// skipped.
type Plan struct {
	Item   Item
	Recipe catalog.Recipe
	Opts   engine.RunOptions
	Skip   string
}

// Prepare builds each item's run options from the shared target (base).
// acp lists the agents burner drives over ACP: an item with a model runs
// over ACP when its agent is in it.
func Prepare(s Series, recipes []catalog.Recipe, base engine.RunOptions, acp []string) []Plan {
	kind := TargetKind(base)
	var out []Plan
	for _, it := range s.Items {
		p := Plan{Item: it}
		r, err := catalog.Find(recipes, it.Recipe)
		if err != nil {
			p.Skip = "unknown recipe"
			out = append(out, p)
			continue
		}
		p.Recipe = r
		if kind != "" && !r.Accepts(kind) {
			p.Skip = "no shared target"
			out = append(out, p)
			continue
		}
		o := base
		o.Recipe = r.EngineRef()
		o.Agent = it.Agent
		o.ACP, o.Model, o.Permission = false, "", ""
		if it.Model != "" && contains(acp, it.Agent) {
			o.ACP, o.Model = true, it.Model
		}
		if r.Scope == "none" || r.Scope == "" {
			o.Scope = ""
		}
		o.Keep = s.Keep
		if o.OnAsk == "" {
			o.OnAsk = "skip" // nobody watches each recipe of a series
		}
		p.Opts = o
		out = append(out, p)
	}
	return out
}

// Run runs the prepared items in order and writes the combined report into
// runsDir/<stamp>-series-<name>/. progress is called before and after each
// item.
func Run(ctx context.Context, s Series, plans []Plan, target, runsDir string, run RunFunc, progress func(i int, r RecipeResult)) (Combined, string, error) {
	c := Combined{Series: s.Name, Target: target, Started: time.Now().Format(time.RFC3339)}
	stopped := false
	for i, p := range plans {
		res := RecipeResult{Recipe: p.Item.Recipe, Agent: p.Item.Agent, Model: p.Item.Model}
		switch {
		case p.Skip != "":
			res.Status, res.Reason = "skipped", p.Skip
		case stopped || ctx.Err() != nil:
			res.Status = "stopped"
		default:
			res.Status = "running"
			if progress != nil {
				progress(i, res)
			}
			report, code, err := run(ctx, p.Opts)
			res.Report = report
			switch {
			case err != nil:
				res.Status, res.Reason = "failed", err.Error()
			case code != 0:
				res.Status, res.Reason = "failed", fmt.Sprintf("exit %d", code)
			default:
				res.Status = "done"
			}
			if res.Status == "failed" && s.OnFailure == "stop" {
				stopped = true
			}
		}
		if res.Report != "" {
			c.Recipes = append(c.Recipes, res)
			c.Findings = Merge(c.Recipes)
			res = c.Recipes[len(c.Recipes)-1]
		} else {
			c.Recipes = append(c.Recipes, res)
		}
		if progress != nil {
			progress(i, res)
		}
	}
	c.Findings = Merge(c.Recipes)
	c.Finished = time.Now().Format(time.RFC3339)
	dir := filepath.Join(runsDir, time.Now().Format("20060102-150405")+"-series-"+s.Name)
	path, err := Write(dir, c)
	return c, path, err
}
