def table_row($mode):
  .value as $v
  | "<tr>"
  + "<td class=\"num\">\(.key + 1)</td>"
  + "<td class=\"severity sev-\($v.severity)\" data-sort-value=\"\($v.rank)\">\($v.severity)</td>"
  + (if $mode == "recent" then "<td class=\"date\">\(($v.changed // "-"))</td>" else "" end)
  + "<td class=\"score\" data-sort-value=\"\($v.cvss_score_sort)\">\($v.cvss_score)</td>"
  + "<td class=\"attack\" data-sort-value=\"\($v.attack_vector_rank)\">\($v.attack_vector)</td>"
  + "<td class=\"complexity\" data-sort-value=\"\($v.attack_complexity_rank)\">\($v.attack_complexity)</td>"
  + "<td class=\"privileges\" data-sort-value=\"\($v.privileges_rank)\">\($v.privileges)</td>"
  + "<td class=\"interaction\" data-sort-value=\"\($v.user_interaction_rank)\">\($v.user_interaction)</td>"
  + "<td class=\"package\">\($v.package)</td>"
  + "<td class=\"version\">\($v.installed)</td>"
  + "<td class=\"fixed\">\($v.fixed)</td>"
  + "<td class=\"target\">\($v.target)</td>"
  + "<td class=\"vuln\"><a href=\"\($v.url)\" target=\"_blank\">\($v.id)</a></td>"
  + "<td class=\"title\">\($v.title | .[0:400])</td>"
  + "</tr>";

def findings($mode):
  if $mode == "recent" then
    [.Results[]? | .Target as $target | .Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH") | select(((.LastModifiedDate // .PublishedDate // "")[0:10]) >= $since) | finding($target) + {changed: ((.LastModifiedDate // .PublishedDate // "-")[0:10])}] | sort_by(.changed, .rank, .package, .id) | reverse
  else
    [.Results[]? | .Target as $target | .Vulnerabilities[]? | finding($target)] | sort_by(.rank, .package, .id)
  end;

"<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\">
<title>Security Dependency Report</title>
<style>
body{font:14px system-ui,sans-serif;margin:24px;color:#202124;background:#fff;}
h1{font-size:22px;margin:0 0 8px;} h2{font-size:18px;margin-top:28px;}
.meta{color:#5f6368;margin-bottom:18px;} .summary{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0;}
.pill{border:1px solid #dadce0;border-radius:6px;padding:6px 10px;background:#f8f9fa;}
.table-wrap{overflow-x:auto;margin-bottom:8px;} table{border-collapse:collapse;width:2400px;max-width:none;table-layout:fixed;} th,td{border-bottom:1px solid #e0e0e0;padding:6px 8px;text-align:left;vertical-align:top;}
th{position:sticky;top:0;background:#f8f9fa;z-index:1;} th[data-sort]{cursor:pointer;user-select:none;} th[aria-sort=\"ascending\"]::after{content:\" ^\";color:#5f6368;} th[aria-sort=\"descending\"]::after{content:\" v\";color:#5f6368;} td{word-break:break-word;} .num{width:48px;color:#5f6368;text-align:right;}
.sev-CRITICAL{color:#b00020;font-weight:700;} .sev-HIGH{color:#d84315;font-weight:700;}
.fixed{width:120px}.version{width:100px}.date{width:100px}.vuln{width:145px}.severity{width:90px}.score{width:70px}.attack{width:110px}.complexity{width:95px}.privileges{width:105px}.interaction{width:105px}.target{width:230px}.package{width:145px}.title{width:520px}
</style></head><body>
<h1>Security Dependency Report</h1>
<div class=\"meta\">Generated: \($generated)<br>Projects: \($projects_dir)<br>Scanner: trivy</div>
<div class=\"summary\">
<div class=\"pill\">Critical: \($critical_count)</div>
<div class=\"pill\">High: \($high_count)</div>
<div class=\"pill\">Medium: \($medium_count)</div>
<div class=\"pill\">Low: \($low_count)</div>
<div class=\"pill\">Total: \($total_count)</div>
<div class=\"pill\">Recent high/critical changes: \($recent_count)</div>
</div>
<h2>Recent High/Critical Changes</h2>
<div class=\"table-wrap\"><table class=\"sortable\"><thead><tr><th class=\"num\" data-sort=\"number\">#</th><th class=\"severity\" data-sort=\"number\">Severity</th><th class=\"date\" data-sort=\"text\">Changed</th><th class=\"score\" data-sort=\"number\">CVSS</th><th class=\"attack\" data-sort=\"number\">Attack vector</th><th class=\"complexity\" data-sort=\"number\">Complexity</th><th class=\"privileges\" data-sort=\"number\">Privileges</th><th class=\"interaction\" data-sort=\"number\">User action</th><th class=\"package\" data-sort=\"text\">Package</th><th class=\"version\" data-sort=\"text\">Installed</th><th class=\"fixed\" data-sort=\"text\">Fixed</th><th class=\"target\" data-sort=\"text\">Target</th><th class=\"vuln\" data-sort=\"text\">Vulnerability</th><th class=\"title\" data-sort=\"text\">Title</th></tr></thead><tbody>"
+ (findings("recent") | to_entries | map(table_row("recent")) | join(""))
+ "</tbody></table></div>
<h2>All Findings</h2>
<div class=\"table-wrap\"><table class=\"sortable\"><thead><tr><th class=\"num\" data-sort=\"number\">#</th><th class=\"severity\" data-sort=\"number\">Severity</th><th class=\"score\" data-sort=\"number\">CVSS</th><th class=\"attack\" data-sort=\"number\">Attack vector</th><th class=\"complexity\" data-sort=\"number\">Complexity</th><th class=\"privileges\" data-sort=\"number\">Privileges</th><th class=\"interaction\" data-sort=\"number\">User action</th><th class=\"package\" data-sort=\"text\">Package</th><th class=\"version\" data-sort=\"text\">Installed</th><th class=\"fixed\" data-sort=\"text\">Fixed</th><th class=\"target\" data-sort=\"text\">Target</th><th class=\"vuln\" data-sort=\"text\">Vulnerability</th><th class=\"title\" data-sort=\"text\">Title</th></tr></thead><tbody>"
+ (findings("all") | to_entries | map(table_row("all")) | join(""))
+ "</tbody></table></div>
<script>
(() => {
  const cellValue = (row, index) => row.children[index]?.dataset.sortValue ?? row.children[index]?.textContent.trim() ?? \"\";
  const coerce = (value, type) => {
    if (type === \"number\") {
      const number = Number.parseFloat(value);
      return Number.isNaN(number) ? -1 : number;
    }
    return value.toLocaleLowerCase();
  };
  document.querySelectorAll(\"table.sortable\").forEach(table => {
    table.querySelectorAll(\"th[data-sort]\").forEach((th, index) => {
      th.tabIndex = 0;
      const sort = () => {
        const tbody = table.tBodies[0];
        const direction = th.dataset.direction === \"asc\" ? \"desc\" : \"asc\";
        const multiplier = direction === \"asc\" ? 1 : -1;
        const type = th.dataset.sort || \"text\";
        const rows = Array.from(tbody.rows);
        rows.sort((left, right) => {
          const a = coerce(cellValue(left, index), type);
          const b = coerce(cellValue(right, index), type);
          if (a < b) return -1 * multiplier;
          if (a > b) return 1 * multiplier;
          return 0;
        });
        rows.forEach(row => tbody.appendChild(row));
        table.querySelectorAll(\"th[aria-sort]\").forEach(header => header.removeAttribute(\"aria-sort\"));
        th.dataset.direction = direction;
        th.setAttribute(\"aria-sort\", direction === \"asc\" ? \"ascending\" : \"descending\");
      };
      th.addEventListener(\"click\", sort);
      th.addEventListener(\"keydown\", event => {
        if (event.key === \"Enter\" || event.key === \" \") {
          event.preventDefault();
          sort();
        }
      });
    });
  });
})();
</script></body></html>"
