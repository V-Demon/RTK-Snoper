# RTK SnopeR

Client HTTP de bureau (Tkinter + **PycURL**) pour rejouer, à partir d'une
bibliothèque de **templates d'attaque JSON externalisée**, les sondes de
vérification associées aux scénarios **RTK Scenario Studio** (SSRF via
outil MCP, fuite de stack trace en mode debug, CORS permissif +
credentials, traversée de chemin, listing public de bucket...).

> ⚠️ **Usage strictement réservé aux engagements de sécurité autorisés.**
> Cet outil **n'exploite aucune vulnérabilité par lui-même** : il
> construit et envoie des requêtes HTTP, puis journalise les réponses.
> L'interprétation (faille confirmée ou non) reste à la charge de
> l'opérateur. N'utilisez cet outil que contre des cibles que vous
> possédez ou que vous êtes explicitement mandaté à tester, dans le cadre
> d'un engagement couvert par un périmètre écrit (`scope.yaml` ou
> équivalent).

## Fonctionnalités

1. **Saisie des paramètres de cible** — URL de bucket, d'API, de fonction,
   de serveur MCP, etc., propres à chaque template (champ libre par
   template, défini dans `attack_templates.json`).
2. **Bibliothèque de templates JSON** — chaque template décrit une
   famille d'attaque (nom, module RTK, références OWASP/MITRE, une ou
   plusieurs requêtes avec `{{placeholders}}`, et une liste
   d'« indicateurs » texte permettant une détection automatique de
   succès dans la réponse).
3. **Génération des requêtes** — les templates sont résolus avec les
   paramètres saisis ; chaque requête générée reste éditable (en-têtes et
   corps) avant envoi, dans l'onglet *Requêtes générées*.
4. **Envoi via PycURL** — exécution asynchrone (thread dédié, l'interface
   ne se fige pas), avec timeout, vérification TLS configurable, en-têtes
   globaux additionnels et jeton `Authorization: Bearer` optionnel.
5. **Récupération des réponses & log détaillé** — statut HTTP, temps de
   réponse, en-têtes et corps de réponse (tronqué à l'affichage),
   correspondance automatique avec les indicateurs du template. Export en
   **JSON Lines** (`.jsonl`, un objet par requête, exploitable par tout
   outil d'analyse) et en **rapport Markdown** prêt à annexer à un
   rapport de pentest.

## Garde-fou d'engagement

Avant tout envoi, l'application exige :

- un **ID d'engagement** et un **nom d'opérateur** non vides ;
- une **case de confirmation** explicite ("j'opère dans le cadre d'un
  engagement autorisé") ;
- un **périmètre autorisé non vide** (liste de domaines/suffixes, un par
  ligne, ex. `*.run.app`, `example.com`).

Toute requête générée dont l'hôte cible ne correspond à **aucune** entrée
du périmètre est automatiquement **ignorée** (et journalisée comme telle,
jamais envoyée). Ce contrôle est déclaratif — il protège contre les
erreurs de copier-coller d'URL, pas contre une volonté délibérée de
contourner le périmètre : la responsabilité de l'autorisation reste
entièrement celle de l'opérateur.

## Installation

```bash
# Dépendance requise : PycURL (bindings Python pour libcurl)
# Debian/Ubuntu : la lib système libcurl4-openssl-dev peut être nécessaire
sudo apt-get install -y libcurl4-openssl-dev python3-tk   # si absent
pip install pycurl --break-system-packages

python3 app.py
```

Les fichiers `app.py` et `attack_templates.json` doivent rester au même
niveau. Si PycURL n'est pas installé, l'application démarre quand même en
**mode aperçu seul** (génération et édition des requêtes possibles, envoi
désactivé) avec un bandeau d'avertissement.

## Format `attack_templates.json`

```json
{
  "templates": [
    {
      "id": "identifiant-unique",
      "name": "Nom affiché",
      "rtk_module": "module.rtk (RTK-XX)",
      "category": "Catégorie",
      "severity": "high",
      "description": "Description du scénario.",
      "owasp": ["A05:2021 – Security Misconfiguration"],
      "mitre_attack": ["T1190: Exploit Public-Facing Application"],
      "parameters": [
        {"key": "target_base_url", "label": "URL de base", "default": "https://CHANGE-ME"}
      ],
      "requests": [
        {
          "name": "Nom de la requête",
          "method": "GET",
          "url": "{{target_base_url}}/chemin",
          "headers": {"Origin": "https://site-tiers.example"},
          "body": ""
        }
      ],
      "indicators": ["chaine-a-rechercher-dans-la-reponse"]
    }
  ]
}
```

- Les paramètres sont injectés via `{{cle}}` — simple substitution de
  texte, sans évaluation de code.
- `indicators` est une liste de sous-chaînes (insensibles à la casse)
  recherchées dans les en-têtes + le corps de la réponse ; toute
  correspondance est signalée en rouge dans l'onglet *Exécution &
  résultats* et listée dans le rapport.
- `requests` peut contenir plusieurs entrées (ex. plusieurs variantes
  d'`Origin`, plusieurs encodages de traversée de chemin) : elles sont
  toutes générées et envoyées séquentiellement.

## 6 templates fournis par défaut

| Template | Module RTK | Sévérité |
|---|---|---|
| SSRF via outil MCP `http_get` | RTK-13/14 | critical |
| Déclenchement de stack trace (debug Flask/Werkzeug) | RTK-02 | high |
| CORS permissif + `Access-Control-Allow-Credentials` | RTK-05 | high |
| Traversée de chemin (sonde multi-encodage) | RTK-05 | medium |
| Listing public de bucket / objet accessible | RTK-04 | high |
| Requête libre (sonde générique) | custom | info |

Ils correspondent exactement aux scénarios déjà déployés par
**RTK Scenario Studio** : déployez un scénario avec ce dernier, récupérez
l'URL du service, déclarez-la dans le périmètre autorisé ici, et lancez
le template correspondant pour vérifier automatiquement la faille.

## Limites connues

- Interface Tkinter mono-fenêtre, pas de gestion de sessions/cookies
  persistantes entre requêtes d'un même template (chaque requête est
  indépendante — ajoutez un en-tête `Cookie` manuellement si nécessaire).
- Les corps de réponse sont tronqués à l'affichage et dans le rapport
  (4000 caractères) pour rester lisibles ; le fichier `.jsonl` exporté
  suit la même troncature.
- Le contrôle de périmètre est une liste blanche déclarative simple
  (suffixe de domaine), pas une résolution DNS/IP ni une vérification de
  certificat de propriété.
- Aucune gestion de proxy HTTP n'est exposée dans l'UI (ajoutable via
  `pycurl.PROXY` si besoin pour un engagement donné).

## Licence & avertissement

Projet pédagogique destiné à la préparation et à l'exécution contrôlée
d'engagements de test d'intrusion cloud **autorisés**, en complément de
RTK Scenario Studio. L'utilisateur reste seul responsable de l'usage fait
de cet outil, de sa conformité au périmètre d'engagement signé, et de la
légalité de chaque requête envoyée.
