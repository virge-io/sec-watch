def severity_rank($severity):
  if $severity == "CRITICAL" then 0
  elif $severity == "HIGH" then 1
  elif $severity == "MEDIUM" then 2
  elif $severity == "LOW" then 3
  else 4 end;

def metric($vector; $key):
  (($vector // "" | split("/") | map(select(startswith($key + ":"))) | first) // "" | split(":")[1]) // "";

def attack_vector_label($code):
  if $code == "N" then "Network"
  elif $code == "A" then "Adjacent"
  elif $code == "L" then "Local"
  elif $code == "P" then "Physical"
  else "-" end;

def attack_vector_rank($code):
  if $code == "N" then 0
  elif $code == "A" then 1
  elif $code == "L" then 2
  elif $code == "P" then 3
  else 9 end;

def complexity_label($code):
  if $code == "L" then "Low"
  elif $code == "M" then "Medium"
  elif $code == "H" then "High"
  else "-" end;

def complexity_rank($code):
  if $code == "L" then 0
  elif $code == "M" then 1
  elif $code == "H" then 2
  else 9 end;

def privilege_label($code):
  if $code == "N" then "None"
  elif $code == "L" then "Low"
  elif $code == "H" then "High"
  else "-" end;

def privilege_rank($code):
  if $code == "N" then 0
  elif $code == "L" then 1
  elif $code == "H" then 2
  else 9 end;

def authentication_label($code):
  if $code == "N" then "Auth: None"
  elif $code == "S" then "Auth: Single"
  elif $code == "M" then "Auth: Multiple"
  else "-" end;

def authentication_rank($code):
  if $code == "N" then 0
  elif $code == "S" then 1
  elif $code == "M" then 2
  else 9 end;

def interaction_label($code):
  if $code == "N" then "None"
  elif $code == "R" then "Required"
  elif $code == "P" then "Passive"
  elif $code == "A" then "Active"
  else "-" end;

def interaction_rank($code):
  if $code == "N" then 0
  elif $code == "P" then 1
  elif $code == "R" then 2
  elif $code == "A" then 3
  else 9 end;

def cvss_entry:
  (.CVSS // {}
    | to_entries
    | map({
        source: .key,
        score: ((.value.V4Score // .value.V3Score // .value.V2Score // 0) | tonumber? // 0),
        vector: (.value.V4Vector // .value.V3Vector // .value.V2Vector // "")
      })
    | sort_by(.score)
    | reverse
    | first) // {source: "", score: -1, vector: ""};

def cvss_summary:
  cvss_entry as $cvss
  | ($cvss.vector // "") as $vector
  | metric($vector; "AV") as $attack_vector
  | metric($vector; "AC") as $complexity
  | metric($vector; "PR") as $privileges
  | metric($vector; "Au") as $authentication
  | metric($vector; "UI") as $interaction
  | {
      score: (if ($cvss.score // -1) >= 0 then ($cvss.score | tostring) else "-" end),
      score_sort: ($cvss.score // -1),
      vector: (if $vector != "" then $vector else "-" end),
      attack_vector: attack_vector_label($attack_vector),
      attack_vector_rank: attack_vector_rank($attack_vector),
      attack_complexity: complexity_label($complexity),
      attack_complexity_rank: complexity_rank($complexity),
      privileges: (if $privileges != "" then privilege_label($privileges) else authentication_label($authentication) end),
      privileges_rank: (if $privileges != "" then privilege_rank($privileges) else authentication_rank($authentication) end),
      user_interaction: interaction_label($interaction),
      user_interaction_rank: interaction_rank($interaction)
    };

def finding($target):
  cvss_summary as $cvss
  | {
      rank: severity_rank(.Severity),
      severity: .Severity,
      package: .PkgName,
      installed: (.InstalledVersion // "-"),
      fixed: (.FixedVersion // "-"),
      target: $target,
      id: .VulnerabilityID,
      url: (.PrimaryURL // ""),
      title: ((.Title // .Description // "") | gsub("[\t\r\n]+"; " ")),
      cvss_score: $cvss.score,
      cvss_score_sort: $cvss.score_sort,
      cvss_vector: $cvss.vector,
      attack_vector: $cvss.attack_vector,
      attack_vector_rank: $cvss.attack_vector_rank,
      attack_complexity: $cvss.attack_complexity,
      attack_complexity_rank: $cvss.attack_complexity_rank,
      privileges: $cvss.privileges,
      privileges_rank: $cvss.privileges_rank,
      user_interaction: $cvss.user_interaction,
      user_interaction_rank: $cvss.user_interaction_rank
    };
