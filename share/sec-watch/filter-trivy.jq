def csv_values($value): $value | split(",") | map(select(length > 0));

csv_values($ecosystems) as $ecosystem_ids
| csv_values($projects) as $project_names
| .Results = [
    .Results[]?
    | select(
        $ecosystem_filter_set != "1" or
        (($ecosystem_ids | length) > 0 and (.Type as $type | $ecosystem_ids | index($type)))
      )
    | select(
        ($project_names | length) == 0 or
        (.Target as $target | ($project_names | map(. as $project | select(($target == $project) or ($target | startswith($project + "/")))) | length) > 0)
      )
  ]
