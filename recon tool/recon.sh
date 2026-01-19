#!/bin/bash
set -euo pipefail
print_logo() {
  cat << "EOF"

██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗████████╗ █████╗  ██████╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████╗   ██║   ███████║██║     █████╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██╔═██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████║   ██║   ██║  ██║╚██████╗██║  ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                                                     
EOF
  echo "                           v1.0 | by cyber_pirate | $(date +'%Y')"
  echo "========================================================================="
  echo
}

# Clear screen and print logo
clear
print_logo
today=$(date)
echo "This scan was created on: $today"
echo

# -------------------------
# defaults
# -------------------------
mode="all"
list_file=""
base_out="recon_results"
alive_check="false"
extensions="php,asp,aspx,jsp,html,js,txt,zip,bak,old,conf,json,xml"

# -------------------------
# SecLists auto integration
# -------------------------
SECLISTS="/usr/share/seclists"

# Directory lists (SecLists first, then fallback)
DEFAULT_DIR_LIST="$SECLISTS/Discovery/Web-Content/directory-list-2.3-medium.txt"
FALLBACK_DIR_LIST_1="$SECLISTS/Discovery/Web-Content/common.txt"
FALLBACK_DIR_LIST_2="/home/abdullah/common.txt"
FALLBACK_DIR_LIST_3="/home/abdullah/common.txt"

# DNS list
DEFAULT_DNS_LIST="$SECLISTS/Discovery/DNS/subdomains-top1million-110000.txt"

# Try to locate AltDNS words list automatically
find_altdns_words() {
  if [[ -f "$SECLISTS/Discovery/DNS/altdns/words.txt" ]]; then
    echo "$SECLISTS/Discovery/DNS/altdns/words.txt"
    return
  fi

  # fallback: search in seclists folder
  local f
  f="$(find "$SECLISTS" -type f -path "*altdns*" -name "words.txt" 2>/dev/null | head -n 1 || true)"
  if [[ -n "$f" ]]; then
    echo "$f"
    return
  fi

  echo ""
}

# choose directory wordlist automatically
if [[ -f "$DEFAULT_DIR_LIST" ]]; then
  wordlist="$DEFAULT_DIR_LIST"
elif [[ -f "$FALLBACK_DIR_LIST_1" ]]; then
  wordlist="$FALLBACK_DIR_LIST_1"
elif [[ -f "$FALLBACK_DIR_LIST_2" ]]; then
  wordlist="$FALLBACK_DIR_LIST_2"
else
  wordlist="$FALLBACK_DIR_LIST_3"   # last try
fi

if [[ -f "$DEFAULT_DNS_LIST" ]]; then
  dns_wordlist="$DEFAULT_DNS_LIST"
else
  dns_wordlist=""
fi

altdns_words="$(find_altdns_words)"

usage() {
  cat << EOF
Recon Script - Help

Usage:
  ./recon.sh [-m MODE] [-l domains.txt] [-o output_dir] [-a] domain1 [domain2 ...]

Modes (-m):
  all             Run everything (default)
  subs-only       Run subdomain enum + altdns (+optional alive check)
  crt-only        Run only certificate recon (crt.sh + certspotter)
  dir-only        Run only directory enumeration (dirsearch + gobuster dir)
  urls-only       Run only URL collectors (wayback/gau/crawlers)

Options:
  -m MODE   Mode (default: all)
  -l FILE   Load domains from file (one per line)
  -o DIR    Output base directory (default: recon_results)
  -a        Alive check using httpx (creates alive.txt)
  -h        Help

Auto Wordlists:
  Dir list     : $wordlist
  DNS list     : ${dns_wordlist:-"(missing -> skipped)"}
  AltDNS words : ${altdns_words:-"(missing -> skipped)"}

Examples:
  ./recon.sh https://example.com
  ./recon.sh -m subs-only -a example.com
  ./recon.sh -m all -l domains.txt -a -o outdir
EOF
  exit 0
}

# -------------------------
# parse flags
# -------------------------
while getopts ":m:l:o:ah" opt; do
  case "$opt" in
    m) mode="$OPTARG" ;;
    l) list_file="$OPTARG" ;;
    o) base_out="$OPTARG" ;;
    a) alive_check="true" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

cli_domains=("$@")

# -------------------------
# read domains from file
# -------------------------
file_domains=()
if [[ -n "$list_file" ]]; then
  [[ ! -f "$list_file" ]] && echo "[-] Domain list file not found: $list_file" && exit 1
  while IFS= read -r line; do
    line="$(echo "$line" | sed 's/#.*//g' | xargs)"
    [[ -z "$line" ]] && continue
    file_domains+=("$line")
  done < "$list_file"
fi

domains=("${file_domains[@]}" "${cli_domains[@]}")
[[ ${#domains[@]} -eq 0 ]] && usage

mkdir -p "$base_out"

# -------------------------
# helper functions
# -------------------------
normalize_target() {
  local input="$1"
  local domain url
  if [[ "$input" =~ ^https?:// ]]; then
    url="$input"
    domain="$(echo "$input" | sed -E 's#https?://##' | cut -d/ -f1)"
  else
    domain="$input"
    url="https://$input"
  fi
  echo "$domain|$url"
}

tool_exists() { command -v "$1" >/dev/null 2>&1; }

# -------------------------
# CERTIFICATE SUBDOMAIN ENUM
# -------------------------
crt_scan() {
  local domain="$1"; local outdir="$2"
  tool_exists curl || { echo "[-] curl missing"; return 1; }
  tool_exists jq || { echo "[-] jq missing"; return 1; }

  echo "[*] crt.sh..."
  curl -sSL --fail "https://crt.sh/?q=${domain}&output=json" -o "$outdir/crtsh.json" || true

  echo "[*] certspotter..."
  curl -sSL --fail "https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names" \
    -o "$outdir/certspotter.json" || true

  tmp="$outdir/.crt_tmp.txt"
  : > "$tmp"

  if [[ -s "$outdir/crtsh.json" ]]; then
    jq -r '.[].name_value' "$outdir/crtsh.json" 2>/dev/null \
      | sed 's/\\n/\n/g' | sed 's/\*\.\?//g' \
      | grep -E "([a-zA-Z0-9_-]+\.)+$domain$" >> "$tmp" || true
  fi

  if [[ -s "$outdir/certspotter.json" ]]; then
    jq -r '.[].dns_names[]?' "$outdir/certspotter.json" 2>/dev/null \
      | sed 's/\*\.\?//g' \
      | grep -E "([a-zA-Z0-9_-]+\.)+$domain$" >> "$tmp" || true
  fi

  sort -u "$tmp" > "$outdir/subdomains_cert.txt"
  rm -f "$tmp"

  echo "[+] Saved: $outdir/subdomains_cert.txt ($(wc -l < "$outdir/subdomains_cert.txt" | tr -d ' ') subs)"
}

# -------------------------
# subdomain tools
# -------------------------
sublist3r_scan() {
  local domain="$1"; local outdir="$2"
  tool_exists sublist3r || { echo "[!] sublist3r not installed, skipping"; return 0; }
  echo "[*] Sublist3r..."
  sublist3r -d "$domain" -o "$outdir/sublist3r.txt" >/dev/null 2>&1 || true
  echo "[+] Saved: $outdir/sublist3r.txt"
}

amass_scan() {
  local domain="$1"; local outdir="$2"
  tool_exists amass || { echo "[!] amass not installed, skipping"; return 0; }
  echo "[*] Amass passive..."
  amass enum -passive -d "$domain" -o "$outdir/amass.txt" >/dev/null 2>&1 || true
  echo "[+] Saved: $outdir/amass.txt"
}

subbrute_scan() {
  local domain="$1"; local outdir="$2"
  tool_exists subbrute || { echo "[!] subbrute not installed (apt doesn't have it), skipping"; return 0; }
  [[ -z "$dns_wordlist" ]] && { echo "[!] DNS wordlist missing, skipping subbrute"; return 0; }

  echo "[*] Subbrute..."
  subbrute "$dns_wordlist" "$domain" > "$outdir/subbrute.txt" 2>/dev/null || true
  echo "[+] Saved: $outdir/subbrute.txt"
}

# ✅ FIXED gobuster dns flags
gobuster_dns_scan() {
  local domain="$1"; local outdir="$2"
  tool_exists gobuster || { echo "[!] gobuster not installed, skipping"; return 0; }
  [[ -z "$dns_wordlist" ]] && { echo "[!] DNS wordlist missing, skipping gobuster dns"; return 0; }

  echo "[*] Gobuster DNS..."
  gobuster dns --domain "$domain" -w "$dns_wordlist" -q -o "$outdir/gobuster_dns.txt" || true
  echo "[+] Saved: $outdir/gobuster_dns.txt"
}

merge_subdomains() {
  local domain="$1"; local outdir="$2"
  echo "[*] Merging subdomains..."

  cat \
    "$outdir/subdomains_cert.txt" \
    "$outdir/sublist3r.txt" \
    "$outdir/amass.txt" \
    "$outdir/subbrute.txt" \
    "$outdir/gobuster_dns.txt" 2>/dev/null \
    | sed 's/\*\.\?//g' \
    | grep -E "([a-zA-Z0-9_-]+\.)+$domain$" \
    | sort -u > "$outdir/subdomains_all.txt" || true

  echo "[+] Saved: $outdir/subdomains_all.txt ($(wc -l < "$outdir/subdomains_all.txt" | tr -d ' ') subs)"
}

altdns_generate() {
  local outdir="$1"
  tool_exists altdns || { echo "[!] altdns not installed, skipping"; return 0; }

  [[ -z "$altdns_words" ]] && { echo "[!] AltDNS words missing, skipping"; return 0; }
  [[ ! -s "$outdir/subdomains_all.txt" ]] && { echo "[!] No subdomains for altdns input, skipping"; return 0; }

  echo "[*] AltDNS generating candidates..."
  altdns -i "$outdir/subdomains_all.txt" -o "$outdir/altdns_candidates.txt" -w "$altdns_words" >/dev/null 2>&1 || true
  echo "[+] Saved: $outdir/altdns_candidates.txt"
}

altdns_resolve() {
  local outdir="$1"
  tool_exists dnsx || { echo "[!] dnsx not installed, skipping resolve"; return 0; }
  [[ ! -s "$outdir/altdns_candidates.txt" ]] && return 0

  echo "[*] Resolving AltDNS candidates with dnsx..."
  cat "$outdir/altdns_candidates.txt" | dnsx -silent > "$outdir/altdns_resolved.txt" || true
  echo "[+] Saved: $outdir/altdns_resolved.txt"
}

merge_subdomains_final() {
  local domain="$1"; local outdir="$2"
  cat "$outdir/subdomains_all.txt" "$outdir/altdns_resolved.txt" 2>/dev/null \
    | grep -E "([a-zA-Z0-9_-]+\.)+$domain$" \
    | sort -u > "$outdir/subdomains_final.txt" || true

  echo "[+] Final: $outdir/subdomains_final.txt ($(wc -l < "$outdir/subdomains_final.txt" | tr -d ' ') subs)"
}

alive_scan() {
  local outdir="$1"
  tool_exists httpx || { echo "[!] httpx missing, skipping alive check"; return 0; }
  [[ ! -s "$outdir/subdomains_final.txt" ]] && { echo "[!] No subdomains_final.txt, skipping alive"; return 0; }

  echo "[*] Alive check (httpx)..."
  cat "$outdir/subdomains_final.txt" | httpx -silent -timeout 8 > "$outdir/alive.txt" || true
  echo "[+] Saved: $outdir/alive.txt ($(wc -l < "$outdir/alive.txt" | tr -d ' ') alive)"
}

# -------------------------
# DIR ENUM
# -------------------------
dirsearch_scan() {
  local url="$1"; local outdir="$2"
  tool_exists dirsearch || { echo "[!] dirsearch not installed, skipping"; return 0; }

  [[ ! -f "$wordlist" ]] && { echo "[-] Dir wordlist missing: $wordlist"; return 0; }

  echo "[*] dirsearch (wordlist: $wordlist)"
  dirsearch -u "$url" -w "$wordlist" -e "$extensions" \
    --format plain --output "$outdir/dirsearch.txt" >/dev/null 2>&1 || true
  echo "[+] Saved: $outdir/dirsearch.txt"
}

gobuster_dir_scan() {
  local domain="$1"; local outdir="$2"
  tool_exists gobuster || { echo "[!] gobuster not installed, skipping"; return 0; }
  [[ ! -f "$wordlist" ]] && { echo "[-] Dir wordlist missing: $wordlist"; return 0; }

  echo "[*] gobuster dir (wordlist: $wordlist)"
  gobuster dir -u "https://$domain" -w "$wordlist" -x "$extensions" -q -o "$outdir/gobuster_dir.txt" || true
  echo "[+] Saved: $outdir/gobuster_dir.txt"
}

# -------------------------
# MAIN LOOP
# -------------------------
for target in "${domains[@]}"; do
  IFS="|" read -r domain url <<< "$(normalize_target "$target")"

  echo "========================================="
  echo "[*] Target: $domain"
  echo "========================================="

  outdir="$base_out/${domain}_recon"
  mkdir -p "$outdir"
  echo "[+] Output directory: $outdir"
  echo

  touch "$outdir/subdomains_cert.txt" "$outdir/sublist3r.txt" "$outdir/amass.txt" "$outdir/subbrute.txt" "$outdir/gobuster_dns.txt"
  touch "$outdir/subdomains_all.txt" "$outdir/altdns_candidates.txt" "$outdir/altdns_resolved.txt" "$outdir/subdomains_final.txt"
  touch "$outdir/dirsearch.txt" "$outdir/gobuster_dir.txt"

  case "$mode" in
    subs-only)
      crt_scan "$domain" "$outdir"
      sublist3r_scan "$domain" "$outdir"
      amass_scan "$domain" "$outdir"
      subbrute_scan "$domain" "$outdir"
      gobuster_dns_scan "$domain" "$outdir"
      merge_subdomains "$domain" "$outdir"
      altdns_generate "$outdir"
      altdns_resolve "$outdir"
      merge_subdomains_final "$domain" "$outdir"
      [[ "$alive_check" == "true" ]] && alive_scan "$outdir"
      ;;
    all)
      crt_scan "$domain" "$outdir"
      sublist3r_scan "$domain" "$outdir"
      amass_scan "$domain" "$outdir"
      subbrute_scan "$domain" "$outdir"
      gobuster_dns_scan "$domain" "$outdir"
      merge_subdomains "$domain" "$outdir"
      altdns_generate "$outdir"
      altdns_resolve "$outdir"
      merge_subdomains_final "$domain" "$outdir"
      [[ "$alive_check" == "true" ]] && alive_scan "$outdir"

      dirsearch_scan "$url" "$outdir"
      gobuster_dir_scan "$domain" "$outdir"
      ;;
    crt-only)
      crt_scan "$domain" "$outdir"
      ;;
    dir-only)
      dirsearch_scan "$url" "$outdir"
      gobuster_dir_scan "$domain" "$outdir"
      ;;
    *)
      echo "[-] Unknown mode: $mode"
      usage
      ;;
  esac

  echo
done

echo "[✓] Recon completed. Results stored in: $base_out"
