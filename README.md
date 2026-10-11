# Xytherion

Agent de monitoring pour serveurs Linux et macOS. Un seul binaire, un dashboard intégré, **aucun compte, aucun cloud, aucune télémétrie** : tout reste sur ta machine.

Après installation, le dashboard est disponible sur **http://localhost:9001**.

## Ce que l'agent surveille

- **Système** : CPU, mémoire, disques, charge, réseau, processus.
- **Historique** : mesures à la seconde pour la dernière heure, puis une moyenne par minute pendant 7 jours (conservée après un redémarrage).
- **Sécurité** : ports ouverts et exposés, état du pare-feu (ufw, firewalld, nftables, iptables, pf), dernières connexions SSH, empreinte des processus.
- **Disponibilité** : moniteurs HTTP/HTTPS (avec expiration du certificat SSL), alertes sur seuils, webhooks, Dead Man's Switch.
- **Flotte** : le dashboard peut afficher plusieurs serveurs (2 dans le plan gratuit).

## Installation

macOS ou Linux (amd64 / arm64) :

```bash
curl -fsSL https://raw.githubusercontent.com/OpenDojoSystems0/xytherion-core/main/install.sh | bash
```

Le script vérifie l'empreinte SHA-256 du binaire avant de l'installer, et propose de démarrer l'agent automatiquement au démarrage (systemd sous Linux, launchd sous macOS).

Avec Homebrew :

```bash
brew tap OpenDojoSystems0/xytherion
brew install xytherion
```

Depuis les sources (Go, voir `go.mod` pour la version) :

```bash
git clone https://github.com/OpenDojoSystems0/xytherion-core
cd xytherion-core
make build        # produit ./bin/xytherion
./bin/xytherion
```

Le dashboard est fourni déjà compilé dans `internal/ui/dist` : aucune dépendance Node.js n'est nécessaire pour compiler l'agent.

## Utilisation

```text
xytherion [--port 9001] [--interval 1s] [--ring 3600] [--cors ORIGINES]
xytherion --version
xytherion --update      # installe la dernière version signée
```

| Variable | Rôle |
| --- | --- |
| `XYTHERION_TOKEN` | Jeton d'accès. Sans jeton, l'API n'est joignable que depuis la machine elle-même. |
| `XYTHERION_ALLOW_REMOTE=1` | Autorise l'accès réseau sans jeton (déconseillé hors réseau de confiance). |
| `XYTHERION_ALLOWED_HOSTS` | Noms de domaine supplémentaires acceptés (protection anti DNS-rebinding). |
| `XYTHERION_DATA_FILE` | Fichier des moniteurs et webhooks. |
| `XYTHERION_AUTO_UPDATE=1` | Installe automatiquement les mises à jour signées. |
| `XYTHERION_UPDATE_URL` | Manifeste signé auto-hébergé, à la place des releases GitHub (HTTPS obligatoire). |

### Accès à distance et jeton

Pour consulter un serveur depuis une autre machine, définis un jeton : une chaîne longue et aléatoire.

```bash
XYTHERION_TOKEN="$(openssl rand -hex 32)" xytherion
```

Ouvre ensuite `http://IP-du-serveur:9001` et colle le jeton dans « Jeton d'accès ». Sans bon jeton, l'API répond 401.

Sous Linux, l'installeur génère un jeton pour le service, l'affiche une seule fois et le range dans `/etc/xytherion/agent.env` (lisible par root uniquement). Pour le relire ou le remplacer :

```bash
sudo cat /etc/xytherion/agent.env
echo "XYTHERION_TOKEN=$(openssl rand -hex 32)" | sudo tee /etc/xytherion/agent.env >/dev/null
sudo chmod 600 /etc/xytherion/agent.env
sudo systemctl restart xytherion
```

Le plus sûr reste de **ne pas exposer le port 9001 sur Internet** : passe par un VPN ou un tunnel SSH, puis ouvre `http://localhost:9001` sur ton ordinateur.

```bash
ssh -L 9001:127.0.0.1:9001 utilisateur@ton-serveur
```

Pour la vue Flotte, utilise le même jeton sur tous tes agents. Derrière un reverse proxy installé sur la même machine, définis toujours un jeton (l'agent voit alors toutes les requêtes comme locales).

## Sécurité

- Sans jeton, l'agent n'écoute que sur `127.0.0.1` et `::1`, et ne s'annonce pas sur le réseau local.
- Protection contre le DNS-rebinding (liste de noms acceptés) et le CSRF (contrôle de l'origine des requêtes qui modifient des données).
- Les requêtes sortantes des moniteurs et webhooks refusent les adresses privées, locales et de métadonnées cloud (anti-SSRF).
- Les commandes système sont lancées depuis des chemins fixes, avec un environnement contrôlé.
- Les données sont stockées avec des droits restreints (`0600`, dossier `0700`).
- Le service systemd est durci (système en lecture seule, pas de nouveaux privilèges, appels réseau limités).

### Mises à jour

Chaque version est **signée (ed25519)** en plus de son empreinte SHA-256 : l'agent refuse tout binaire dont la signature est invalide. Le téléchargement se fait en HTTPS uniquement. Les installations Homebrew sont mises à jour avec `brew upgrade xytherion`.

Un problème de sécurité ? Ouvre une *security advisory* privée sur GitHub plutôt qu'une issue publique.

## Désinstallation

```bash
curl -fsSL https://raw.githubusercontent.com/OpenDojoSystems0/xytherion-core/main/uninstall.sh | bash
```

## Développement

```bash
make test         # go vet + go test
make dev          # lance l'agent depuis les sources
```

## Licence

[MIT](LICENSE). Une offre Pro est prévue à part, avec sa propre licence ; elle ne fait pas partie de ce dépôt.
