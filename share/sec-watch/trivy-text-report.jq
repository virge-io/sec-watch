def block:
  "\( .key + 1 ). \(.value.severity) \(.value.id) (CVSS \(.value.cvss_score))\n"
  + "   Package: \(.value.package) \(.value.installed) -> \(.value.fixed)\n"
  + "   Target: \(.value.target)\n"
  + (if .value.changed != null then "   Changed: \(.value.changed)\n" else "" end)
  + "   Attack: vector=\(.value.attack_vector), complexity=\(.value.attack_complexity), privileges=\(.value.privileges), user_action=\(.value.user_interaction)\n"
  + "   Title: \(.value.title | .[0:220])\n"
  + (if .value.url != "" then "   URL: \(.value.url)\n" else "" end);

if $mode == "recent" then
  [.Results[]?
    | .Target as $target
    | .Vulnerabilities[]?
    | select(.Severity == "CRITICAL" or .Severity == "HIGH")
    | select(((.LastModifiedDate // .PublishedDate // "")[0:10]) >= $since)
    | finding($target) + {changed: ((.LastModifiedDate // .PublishedDate // "-")[0:10])}]
  | sort_by(.changed, .rank, .package, .id)
  | reverse
  | to_entries[]
  | block
else
  [.Results[]?
    | .Target as $target
    | .Vulnerabilities[]?
    | finding($target)]
  | sort_by(.rank, .package, .id)
  | to_entries[]
  | block
end
