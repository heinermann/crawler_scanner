
> "2013-20.txt"

while read -r url; do
  curl "https://data.commoncrawl.org/$url" | \
  gzip -dc | \
  grep -iEo '\{"url":\s*"[^"]*\.(scm|scx|rep|pud|zip|rar)(\?[^"#]*|#[^"#]*)?".*\}$' |
  jq -c 'select(.status == "200") | {url, length, offset, filename}' >> "2013-20.txt"
done < "cc-index.paths"
