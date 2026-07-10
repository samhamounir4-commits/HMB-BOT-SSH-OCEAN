# SSHOcean Monitor Bot

Bot Telegram propre et simplifié pour surveiller automatiquement les serveurs SSHOcean.

## Ce que fait le bot

- Vérification automatique toutes les 5 minutes exactes
- Détection des changements d’état
- Notifications Telegram quand un serveur passe de Offline à Online
- Commandes utiles et propres
- Endpoint health pour Render / UptimeRobot

## Commandes

- `/start`
- `/status`
- `/check`
- `/servers`
- `/online`
- `/offline`
- `/summary`
- `/help`

## Installation

```bash
git clone https://github.com/VOTRE_COMPTE/sshocean-monitor.git
cd sshocean-monitor
pip install -r requirements.txt
