# Xytherion

Un agent de monitoring pour serveurs Linux et Mac. Un seul binaire, un dashboard intégré, pas de compte, pas de cloud, rien ne sort de ta machine.

On l'a écrit parce qu'on en avait marre de monter une stack complète (base de métriques, exporters, alerting, dashboards) juste pour savoir si un serveur va bien. Ici tu lances un programme et tu ouvres http://localhost:9001.

Il suit le CPU, la mémoire, les disques, la charge, le réseau et les processus. Il garde l'historique à la minute pendant 7 jours, même après un redémarrage. Il regarde aussi les ports ouverts, le pare-feu (ufw, firewalld, nftables, iptables, pf), les dernières connexions SSH, et il peut surveiller des URL (avec la date d'expiration du certificat), envoyer des alertes sur seuils et appeler des webhooks. Quand un agent disparaît, le dashboard fait la différence entre un arrêt propre et un crash ou une coupure réseau (le Dead Man's Switch). Il sait aussi afficher plusieurs serveurs, deux dans la version gratuite.

## Installer

Sur Linux ou macOS (amd64 et arm64) :

```bash
curl -fsSL https://raw.githubusercontent.com/OpenDojoSystems0/xytherion-core/main/install.sh | bash
```

Le script vérifie l'empreinte SHA-256 du binaire avant de l'installer, puis te demande si l'agent doit démarrer tout seul au boot (systemd sur Linux, launchd sur Mac).

Avec Homebrew :

```bash
brew tap OpenDojoSystems0/xytherion
brew install xytherion
```

Ou depuis les sources, avec la version de Go indiquée dans `go.mod` :

```bash
git clone https://github.com/OpenDojoSystems0/xytherion-core
cd xytherion-core
make build
./bin/xytherion
```

Le dashboard est déjà compilé dans `internal/ui/dist`, donc pas besoin de Node pour compiler l'agent.

## Utilisation

```text
xytherion [--port 9001] [--interval 1s] [--ring 3600] [--cors ORIGINES]
xytherion --version
xytherion --update
```

Quelques variables d'environnement :

| Variable | Effet |
| --- | --- |
| `XYTHERION_TOKEN` | Jeton d'accès. Sans lui, l'API n'est joignable que depuis la machine. |
| `XYTHERION_ALLOW_REMOTE=1` | Ouvre l'accès réseau sans jeton (à éviter hors réseau de confiance). |
| `XYTHERION_ALLOWED_HOSTS` | Noms de domaine acceptés en plus, pour passer derrière un domaine. |
| `XYTHERION_DATA_FILE` | Où stocker les moniteurs et les webhooks. |
| `XYTHERION_AUTO_UPDATE=1` | Installe les mises à jour signées sans demander. |
| `XYTHERION_UPDATE_URL` | Manifeste signé auto-hébergé à la place des releases GitHub (HTTPS obligatoire). |

### Consulter un serveur à distance

Par défaut l'agent n'écoute que sur 127.0.0.1 et ::1. Pour le consulter depuis une autre machine, définis un jeton long et aléatoire :

```bash
XYTHERION_TOKEN="$(openssl rand -hex 32)" xytherion
```

Ouvre ensuite `http://IP-du-serveur:9001` et colle le jeton dans le champ « Jeton d'accès ». Sans le bon jeton, l'API répond 401.

Avec le service Linux installé par le script, un jeton est généré à l'installation, affiché une fois, et rangé dans `/etc/xytherion/agent.env` (lisible par root seulement). Pour le relire ou le changer :

```bash
sudo cat /etc/xytherion/agent.env
echo "XYTHERION_TOKEN=$(openssl rand -hex 32)" | sudo tee /etc/xytherion/agent.env >/dev/null
sudo chmod 600 /etc/xytherion/agent.env
sudo systemctl restart xytherion
```

Le plus propre reste de ne pas exposer le port 9001 sur Internet. Passe par un VPN ou un tunnel SSH, puis ouvre http://localhost:9001 sur ton poste :

```bash
ssh -L 9001:127.0.0.1:9001 utilisateur@ton-serveur
```

Pour la vue multi-serveurs, utilise le même jeton partout. Et si tu mets l'agent derrière un reverse proxy sur la même machine, mets toujours un jeton : l'agent voit alors toutes les requêtes comme locales.

## Sécurité

Sans jeton, l'agent n'écoute que sur la machine et ne s'annonce pas sur le réseau. Les noms d'hôte inconnus sont refusés (anti DNS rebinding), les requêtes qui modifient des données doivent venir du bon site (anti CSRF), et les moniteurs et webhooks ne peuvent pas viser des adresses privées ou les métadonnées cloud (anti SSRF). Les commandes système sont lancées depuis des chemins fixes, les fichiers de données sont en 0600, et le service systemd tourne avec un système de fichiers en lecture seule, sans nouveaux privilèges.

Les mises à jour sont signées en ed25519 en plus de leur empreinte SHA-256, et téléchargées en HTTPS uniquement. L'agent refuse tout binaire dont la signature ne correspond pas à la clé publique intégrée au code. Si tu as installé avec Homebrew, mets à jour avec `brew upgrade xytherion`.

Si tu trouves une faille, ouvre un signalement privé depuis l'onglet Security du dépôt plutôt qu'une issue publique.

## Désinstaller

```bash
curl -fsSL https://raw.githubusercontent.com/OpenDojoSystems0/xytherion-core/main/uninstall.sh | bash
```

## Développer

`make dev` lance l'agent depuis les sources, `make test` fait un `go vet` puis les tests.

## Licence

MIT, voir [LICENSE](LICENSE). Une offre Pro est prévue à part, sous sa propre licence, et ne fait pas partie de ce dépôt.
