#!/usr/bin/env bash
# Répare /var/ossec/etc/rules/local_rules.xml et y installe UNE seule fois
# les règles de corrélation 100117 / 100118 / 100119.
#
# À lancer sur le manager Wazuh :
#   sudo bash fix-correlation-rules.sh                  # simulation : montre le diff, ne touche à rien
#   sudo bash fix-correlation-rules.sh --apply          # installe, teste (analysisd -t), redémarre
#   ... --attack-stage                                  # ajoute aussi attack_stage, aux règles 100111/113/114/115/116 (pas 100110 : l'étape SSH est portée par 100117)
#   ... --from <fichier>                                # force la source (sinon : fichier courant s'il est lisible, sinon le .bak.* le plus récent lisible)
set -euo pipefail

RULES=${RULES:-/var/ossec/etc/rules/local_rules.xml}
APPLY=0; ATTACK_STAGE=0; SRC=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --attack-stage) ATTACK_STAGE=1 ;;
    --from) SRC="$2"; shift ;;
    *) echo "Option inconnue : $1" >&2; exit 2 ;;
  esac
  shift
done

[ "$APPLY" -eq 0 ] || [ "$(id -u)" -eq 0 ] || { echo "À lancer avec sudo." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 requis." >&2; exit 1; }

# Teste si un fichier de règles est du XML bien formé (plusieurs <group> racines → on l'enveloppe)
parses() {
  python3 - "$1" <<'PY' 2>/dev/null
import re, sys, xml.etree.ElementTree as ET
t = re.sub(r'^\s*<\?xml[^>]*\?>', '', open(sys.argv[1], encoding='utf-8').read())
ET.fromstring('<root>' + t + '</root>')
PY
}

echo "== Sauvegardes disponibles"
ls -lt "$RULES".bak.* 2>/dev/null || echo "(aucune)"

if [ -z "$SRC" ]; then
  if parses "$RULES"; then
    SRC="$RULES"
  else
    echo "Fichier courant malformé → recherche d'une sauvegarde bien formée"
    for f in $(ls -t "$RULES".bak.* 2>/dev/null); do
      if parses "$f"; then SRC="$f"; break; fi
      echo "  ignorée (malformée) : $f"
    done
  fi
fi
[ -n "$SRC" ] || { echo "Aucune source bien formée trouvée. Utilise --from <fichier>." >&2; exit 1; }
parses "$SRC" || { echo "Source malformée : $SRC" >&2; exit 1; }
echo "== Source retenue : $SRC"

CANDIDATE=$(mktemp /tmp/local_rules.XXXXXX.xml)
python3 - "$SRC" "$CANDIDATE" "$ATTACK_STAGE" <<'PY'
import re, sys, xml.etree.ElementTree as ET

src, out, attack_stage = sys.argv[1], sys.argv[2], sys.argv[3] == '1'
TARGETS = {'100117', '100118', '100119'}
STAGE_RULES = {'100111', '100113', '100114', '100115', '100116'}

NEW_RULES = '''
<group name="syslog,sshd,">
  <rule id="100117" level="14">
    <if_sid>5715</if_sid>
    <if_matched_sid>100110</if_matched_sid>
    <same_source_ip />
    <description>SSH : connexion réussie depuis $(srcip) après un brute force — compromission probable du compte</description>
    <mitre>
      <id>T1110</id>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,compromise,attack_stage,</group>
  </rule>
</group>

<group name="windows,windows_security,account_management,">
  <rule id="100118" level="14">
    <if_sid>100113</if_sid>
    <if_matched_sid>60109</if_matched_sid>
    <same_location />
    <description>Windows : compte créé puis ajouté aux Administrateurs dans la foulée — persistance + élévation (compromission probable)</description>
    <mitre>
      <id>T1136</id>
      <id>T1098</id>
    </mitre>
    <group>account_management,privilege_escalation,compromise,attack_stage,</group>
  </rule>
</group>

<group name="correlation,">
  <rule id="100119" level="15" frequency="3" timeframe="900">
    <if_matched_group>attack_stage</if_matched_group>
    <description>Scénario d'intrusion multi-étapes : plusieurs détections critiques corrélées en moins de 15 min — compromission probable</description>
    <group>compromise,attack_chain,</group>
  </rule>
</group>
'''

def parse(text):
    text = re.sub(r'^\s*<\?xml[^>]*\?>', '', text)
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    parser.feed('<root>' + text + '</root>')
    return parser.close()

root = parse(open(src, encoding='utf-8').read())

# 1. Retire toutes les occurrences de 100117-100119 (blocs <group> entiers s'ils ne contiennent que celles-là)
removed = 0
for grp in list(root):
    if grp.tag != 'group':
        continue
    rules = grp.findall('rule')
    bad = [r for r in rules if r.get('id') in TARGETS]
    if not bad:
        continue
    if len(bad) == len(rules):
        root.remove(grp)
    else:
        for r in bad:
            grp.remove(r)
    removed += len(bad)
print(f"Occurrences 100117-100119 retirées : {removed}")

# 2. Optionnel : tag attack_stage sur les règles de détection existantes
if attack_stage:
    for rule in root.iter('rule'):
        if rule.get('id') not in STAGE_RULES:
            continue
        g = rule.find('group')
        if g is None:
            g = ET.SubElement(rule, 'group')
            g.text = ''
        if 'attack_stage' not in (g.text or ''):
            txt = (g.text or '').strip()
            g.text = txt + ('' if not txt or txt.endswith(',') else ',') + 'attack_stage,'
            print(f"attack_stage ajouté à {rule.get('id')}")

# 3. Ajoute la version correcte, une seule fois
if len(root):
    root[-1].tail = (root[-1].tail or '').rstrip() + '\n'
for grp in parse(NEW_RULES):
    root.append(grp)

ids = [r.get('id') for r in root.iter('rule')]
dups = sorted({i for i in ids if ids.count(i) > 1})
if dups:
    sys.exit(f"IDs en double après réparation : {dups}")

body = ET.tostring(root, encoding='unicode')
body = body[len('<root>'):-len('</root>')].replace('&gt;', '>')
open(out, 'w', encoding='utf-8', newline='\n').write(body.strip('\n') + '\n')
PY

echo "== Diff (source → résultat)"
diff -u "$SRC" "$CANDIDATE" || true

if [ "$APPLY" -ne 1 ]; then
  echo
  echo "Simulation uniquement. Résultat : $CANDIDATE"
  echo "Relance avec --apply pour installer."
  exit 0
fi

STAMP=$(date +%Y%m%d-%H%M%S)
cp -p "$RULES" "$RULES.broken.$STAMP"
echo "== Fichier courant sauvegardé : $RULES.broken.$STAMP"
cat "$CANDIDATE" > "$RULES"          # écrase le contenu en gardant propriétaire/permissions
chown root:wazuh "$RULES" && chmod 660 "$RULES"

echo "== wazuh-analysisd -t"
if /var/ossec/bin/wazuh-analysisd -t; then
  systemctl restart wazuh-manager
  systemctl is-active wazuh-manager
  grep -c 'rule id="10011[789]"' "$RULES" | xargs echo "Règles 100117-119 présentes :"
else
  echo "Test KO → remise en place du fichier précédent ($RULES.broken.$STAMP)." >&2
  cp -p "$RULES.broken.$STAMP" "$RULES"
  exit 1
fi
