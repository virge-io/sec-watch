package report

import (
	"html/template"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/virge/sec-watch/internal/cache"
	"github.com/virge/sec-watch/internal/scanner"
)

var htmlTmpl = template.Must(template.New("html").Funcs(template.FuncMap{
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n]
	},
	"add1": func(n int) int { return n + 1 },
	"fixCell": func(f Finding) template.HTML {
		if !f.Indirect {
			return template.HTML(template.HTMLEscapeString(f.Fixed))
		}
		if f.Fixed != "-" {
			return template.HTML("needs &gt;= " + template.HTMLEscapeString(f.Fixed))
		}
		return template.HTML("no fix known")
	},
	"viaCell": func(f Finding) template.HTML {
		if len(f.Via) == 0 {
			return ""
		}
		var sb strings.Builder
		for i, ve := range f.Via {
			if i > 0 {
				sb.WriteString(`<div style="margin-top:6px">`)
			} else {
				sb.WriteString("<div>")
			}
			sb.WriteString("<strong>via " + template.HTMLEscapeString(ve.Pkg) + "</strong>")
			if ve.Advice != "" {
				sb.WriteString("<br><small>" + template.HTMLEscapeString(ve.Advice) + "</small>")
			}
			sb.WriteString("</div>")
		}
		return template.HTML(sb.String())
	},
	"targetRelative": func(target, project string) string {
		return strings.TrimPrefix(target, project+"/")
	},
}).Parse(htmlTemplate))

func groupByProject(findings []Finding, projectsDir string) []ProjectGroup {
	base := filepath.Base(projectsDir)
	var order []string
	groups := map[string][]Finding{}
	for _, f := range findings {
		name := base
		if i := strings.Index(f.Target, "/"); i > 0 {
			name = f.Target[:i]
		}
		if _, seen := groups[name]; !seen {
			order = append(order, name)
		}
		groups[name] = append(groups[name], f)
	}
	out := make([]ProjectGroup, len(order))
	for i, name := range order {
		out[i] = ProjectGroup{Name: name, Findings: groups[name]}
	}
	return out
}

type ProjectGroup struct {
	Name     string
	Findings []Finding
}

type htmlData struct {
	Generated   string
	ProjectsDir string
	Stats       *cache.Status
	Projects    []ProjectGroup
}

func WriteHTML(w io.Writer, result *scanner.TrivyResult, s *cache.Status, projectsDir string) error {
	generated := time.Now().Format("2006-01-02 15:04:05")

	all := AllFindings(result)
	sort.Slice(all, func(i, j int) bool {
		if all[i].Rank != all[j].Rank {
			return all[i].Rank < all[j].Rank
		}
		if all[i].Package != all[j].Package {
			return all[i].Package < all[j].Package
		}
		return all[i].ID < all[j].ID
	})

	return htmlTmpl.Execute(w, htmlData{
		Generated:   generated,
		ProjectsDir: projectsDir,
		Stats:       s,
		Projects:    groupByProject(all, projectsDir),
	})
}



const htmlTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Security Dependency Report</title>
<style>
body{font:14px system-ui,sans-serif;margin:24px;color:#202124;background:#fff;}
h1{font-size:22px;margin:0 0 8px;} h2{font-size:18px;margin-top:32px;margin-bottom:6px;}
.meta{color:#5f6368;margin-bottom:18px;} .summary{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0;}
.pill{border:1px solid #dadce0;border-radius:6px;padding:6px 10px;background:#f8f9fa;}
.table-wrap{overflow-x:auto;margin-bottom:8px;} table{border-collapse:collapse;width:2400px;max-width:none;table-layout:fixed;} th,td{border-bottom:1px solid #e0e0e0;padding:6px 8px;text-align:left;vertical-align:top;}
th{position:sticky;top:0;background:#f8f9fa;z-index:1;} th[data-sort]{cursor:pointer;user-select:none;} th[aria-sort="ascending"]::after{content:" ^";color:#5f6368;} th[aria-sort="descending"]::after{content:" v";color:#5f6368;} td{word-break:break-word;} .num{width:48px;color:#5f6368;text-align:right;}
.sev-CRITICAL{color:#b00020;font-weight:700;} .sev-HIGH{color:#d84315;font-weight:700;}
.badge-indirect{display:inline-block;font-size:11px;font-weight:600;color:#5f4f00;background:#fff8e1;border:1px solid #ffe082;border-radius:4px;padding:0 4px;margin-left:4px;vertical-align:middle;}
.via-entry strong{font-size:13px;} .via-entry small{color:#5f6368;font-size:11px;}
.fixed{width:120px}.via{width:260px}.version{width:100px}.vuln{width:145px}.severity{width:90px}.score{width:70px}.attack{width:110px}.complexity{width:95px}.privileges{width:105px}.interaction{width:105px}.target{width:160px}.package{width:145px}.title{width:470px}
</style></head><body>
<h1>Security Dependency Report</h1>
<div class="meta">Generated: {{.Generated}}<br>Projects: {{.ProjectsDir}}<br>Scanner: trivy</div>
<div class="summary">
<div class="pill">Critical: {{.Stats.DepCriticalCount}}</div>
<div class="pill">High: {{.Stats.DepHighCount}}</div>
<div class="pill">Medium: {{.Stats.DepMediumCount}}</div>
<div class="pill">Low: {{.Stats.DepLowCount}}</div>
<div class="pill">Total: {{.Stats.DepCount}}</div>
</div>
{{if .Projects}}{{range .Projects}}
<h2>{{.Name}}</h2>
<div class="table-wrap"><table class="sortable"><thead><tr>
<th class="num" data-sort="number">#</th>
<th class="severity" data-sort="number">Severity</th>
<th class="score" data-sort="number">CVSS</th>
<th class="attack" data-sort="number">Attack vector</th>
<th class="complexity" data-sort="number">Complexity</th>
<th class="privileges" data-sort="number">Privileges</th>
<th class="interaction" data-sort="number">User action</th>
<th class="package" data-sort="text">Package</th>
<th class="version" data-sort="text">Installed</th>
<th class="fixed" data-sort="text">Fix</th>
<th class="via" data-sort="text">Via</th>
<th class="target" data-sort="text">Target</th>
<th class="vuln" data-sort="text">Vulnerability</th>
<th class="title" data-sort="text">Title</th>
</tr></thead><tbody>
{{$proj := .Name}}{{range $i, $f := .Findings}}<tr>
<td class="num">{{add1 $i}}</td>
<td class="severity sev-{{$f.Severity}}" data-sort-value="{{$f.Rank}}">{{$f.Severity}}</td>
<td class="score" data-sort-value="{{$f.CVSSScore}}">{{$f.CVSSScoreStr}}</td>
<td class="attack" data-sort-value="{{$f.AttackVectorRank}}">{{$f.AttackVector}}</td>
<td class="complexity" data-sort-value="{{$f.AttackComplexRank}}">{{$f.AttackComplexity}}</td>
<td class="privileges" data-sort-value="{{$f.PrivilegesRank}}">{{$f.Privileges}}</td>
<td class="interaction" data-sort-value="{{$f.UserInteractRank}}">{{$f.UserInteraction}}</td>
<td class="package">{{$f.Package}}{{if $f.Indirect}}<span class="badge-indirect">indirect</span>{{end}}</td>
<td class="version">{{$f.Installed}}</td>
<td class="fixed">{{fixCell $f}}</td>
<td class="via">{{viaCell $f}}</td>
<td class="target">{{targetRelative $f.Target $proj}}</td>
<td class="vuln"><a href="{{$f.URL}}" target="_blank">{{$f.ID}}</a></td>
<td class="title">{{truncate $f.Title 400}}</td>
</tr>{{end}}
</tbody></table></div>
{{end}}{{else}}<p>No dependency vulnerabilities found.</p>{{end}}
<script>
(() => {
  const cellValue = (row, index) => row.children[index]?.dataset.sortValue ?? row.children[index]?.textContent.trim() ?? "";
  const coerce = (value, type) => {
    if (type === "number") { const n = Number.parseFloat(value); return Number.isNaN(n) ? -1 : n; }
    return value.toLocaleLowerCase();
  };
  document.querySelectorAll("table.sortable").forEach(table => {
    table.querySelectorAll("th[data-sort]").forEach((th, index) => {
      th.tabIndex = 0;
      const sort = () => {
        const tbody = table.tBodies[0];
        const direction = th.dataset.direction === "asc" ? "desc" : "asc";
        const multiplier = direction === "asc" ? 1 : -1;
        const type = th.dataset.sort || "text";
        const rows = Array.from(tbody.rows);
        rows.sort((l, r) => {
          const a = coerce(cellValue(l, index), type);
          const b = coerce(cellValue(r, index), type);
          if (a < b) return -1 * multiplier;
          if (a > b) return 1 * multiplier;
          return 0;
        });
        rows.forEach(row => tbody.appendChild(row));
        table.querySelectorAll("th[aria-sort]").forEach(h => h.removeAttribute("aria-sort"));
        th.dataset.direction = direction;
        th.setAttribute("aria-sort", direction === "asc" ? "ascending" : "descending");
      };
      th.addEventListener("click", sort);
      th.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sort(); } });
    });
  });
})();
</script></body></html>`
