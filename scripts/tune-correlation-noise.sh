#!/usr/bin/env bash
# Évite qu'un simple brute force déclenche la méta-règle 100119 (3 × attack_stage en 15 min) :
#   - 100111 (brute force RDP/SMB) : ignore="900" → une alerte au plus toutes les 15 min
#   - 100110 (brute force SSH)     : retire attack_stage, ; pas d'ignore car 100117
#     (if_matched_sid 100110) a besoin d'une 100110 récente pendant tout le brute force.
#     L'étape SSH de la kill-chain est portée par 100117.
#
# À lancer sur le manager Wazuh :
#   sudo bash tune-correlation-noise.sh            # simulation : montre le diff
#   sudo bash tune-correlation-noise.sh --apply    # installe, teste (analysisd -t), redémarre
set -euo pipefail

RULES=${RULES:-/var/ossec/etc/rules/local_rules.xml}
APPLY=0
case "${1:-}" in
  --apply) APPLY=1 ;;
  "") ;;
  *) echo "Option inconnue : $1" >&2; exit 2 ;;
esac

[ "$APPLY" -eq 0 ] || [ "$(id -u)" -eq 0 ] || { echo "À lancer avec sudo." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 requis." >&2; exit 1; }

CANDIDATE=$(mktemp /tmp/local_rules.XXXXXX.xml)
python3 - "$RULES" "$CANDIDATE" <<'PY'
import re, sys, xml.etree.ElementTree as ET

src, out = sys.argv[1], sys.argv[2]

text = re.sub(r'^\s*<\?xml[^>]*\?>', '', open(src, encoding='utf-8').read())
parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
parser.feed('<root>' + text + '</root>')
root = parser.close()

rules = {r.get('id'): r for r in root.iter('rule')}
for rid in ('100110', '100111'):
    if rid not in rules:
        sys.exit(f"Règle {rid} introuvable dans {src}")

r111 = rules['100111']
if r111.get('ignore') != '900':
    r111.set('ignore', '900')
    print('100111 : ignore="900" ajouté')

g = rules['100110'].find('group')
if g is not None and 'attack_stage' in (g.text or ''):
    g.text = ','.join(x for x in g.text.split(',') if x.strip() != 'attack_stage')
    print('100110 : attack_stage retiré')

body = ET.tostring(root, encoding='unicode')
body = body[len('<root>'):-len('</root>')].replace('&gt;', '>')
open(out, 'w', encoding='utf-8', newline='\n').write(body.strip('\n') + '\n')
PY

echo "== Diff (actuel → résultat)"
if diff -u "$RULES" "$CANDIDATE"; then
  echo "Déjà à jour, rien à faire."
  exit 0
fi

if [ "$APPLY" -ne 1 ]; then
  echo
  echo "Simulation uniquement. Résultat : $CANDIDATE"
  echo "Relance avec --apply pour installer."
  exit 0
fi

STAMP=$(date +%Y%m%d-%H%M%S)
cp -p "$RULES" "$RULES.bak.$STAMP"
echo "== Sauvegarde : $RULES.bak.$STAMP"
cat "$CANDIDATE" > "$RULES"
chown root:wazuh "$RULES" && chmod 660 "$RULES"

echo "== wazuh-analysisd -t"
if /var/ossec/bin/wazuh-analysisd -t; then
  systemctl restart wazuh-manager
  systemctl is-active wazuh-manager
else
  echo "Test KO → remise en place de la sauvegarde." >&2
  cp -p "$RULES.bak.$STAMP" "$RULES"
  exit 1
fi
