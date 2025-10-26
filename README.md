# 🚀 Secure RDP Watch 2025


**Ayi NEDJIMI Consultants - WinToolsSuite**

## 📋 Description

Monitoring RDP avancé avec détection d'attaques brute-force, corrélation de télémétrie RD Gateway, mapping de sessions actives et système de blacklist automatique.


## ✨ Fonctionnalités

- **Monitoring événements RDP**: Subscription Event Log Security pour Event ID 4624 (Type 10=RemoteInteractive) et 4625 (échecs)
- **Détection brute-force**: Agrégation échecs par IP source (> seuil en 5 min = brute-force)
- **Corrélation RD Gateway**: Analyse Event ID 300 dans TerminalServices-Gateway
- **Mapping sessions**: WTSEnumerateSessions pour sessions actives
- **Extraction détails**: UserName, SessionName, State (Active/Disconnected), IdleTime
- **Détection anomalies**: Connexions multiples même user, IPs inhabituelles
- **Blacklist automatique**: Ajout IP lors détection brute-force
- **Configuration seuils**: Personnalisation du seuil brute-force
- **Export CSV UTF-8 BOM**: Sauvegarde des événements et alertes


## 🔌 APIs Utilisées

- `wevtapi.lib`: EvtQuery pour lecture logs Security et TerminalServices-Gateway
- `wtsapi32.lib`: WTSEnumerateSessions, WTSQuerySessionInformation pour sessions
- `comctl32.lib`: ListView, StatusBar


## Compilation

```batch
go.bat
```

Ou manuellement:
```batch
cl.exe /EHsc /std:c++17 SecureRDPWatch2025.cpp wevtapi.lib wtsapi32.lib comctl32.lib user32.lib gdi32.lib advapi32.lib /link /SUBSYSTEM:WINDOWS
```


## 🚀 Utilisation

1. **Démarrer monitoring**: Lance l'analyse des événements RDP
2. **Configurer seuils**: Définit le nombre d'échecs pour détection brute-force
3. **Blacklist IP**: Ajoute manuellement une IP à la blacklist
4. **Exporter**: Sauvegarde en CSV UTF-8


## Détection Brute-Force

- **Seuil par défaut**: 5 échecs en 5 minutes
- **Action automatique**: Ajout IP à la blacklist
- **Nettoyage**: Entrées > 5 minutes sont supprimées automatiquement


## Event IDs Surveillés

- **4624**: Ouverture de session réussie (LogonType 10 = RemoteInteractive/RDP)
- **4625**: Échec d'ouverture de session (tentative RDP échouée)
- **300**: RD Gateway (TerminalServices-Gateway) - Connexion passerelle


## Types d'Alertes

- **BRUTE-FORCE DÉTECTÉ**: > seuil échecs depuis même IP
- **IP BLACKLISTÉE**: Tentative connexion depuis IP blacklistée
- **Connexion suspecte**: Patterns anormaux détectés
- **Session zombie**: Session déconnectée depuis longtemps


## 📌 Prérequis

- Privilèges administrateur pour accès Security log
- Windows Vista/Server 2008 minimum
- RDP activé pour monitoring sessions
- Audit de connexion activé (Group Policy)


## ⚙️ Configuration Audit

Activer l'audit des connexions via GPO:
```
Computer Configuration > Policies > Windows Settings > Security Settings >
Advanced Audit Policy Configuration > Logon/Logoff > Audit Logon
```


## Logging

Logs sauvegardés dans: `%TEMP%\SecureRDPWatch2025.log`


## Structure

- **AutoHandle RAII**: Gestion automatique EVT_HANDLE
- **Threading**: Monitoring asynchrone via std::thread
- **Chrono**: Gestion temporelle pour détection brute-force
- **UI Française**: Interface complète en français


## 💬 Notes

- Limite à 500 événements pour performance optimale
- Blacklist persistante durant l'exécution (non sauvegardée)
- Corrélation sessions actives via WTS API
- Détection basée sur fenêtre glissante de 5 minutes


## Améliorations Possibles

- Sauvegarde persistante blacklist (fichier/registre)
- Intégration Windows Firewall pour blocage automatique
- Alertes email/SIEM lors détection brute-force
- Support RD Gateway logs complet (Event ID 300+)

- --

**WinToolsSuite** - Sécurité et Administration Windows
Ayi NEDJIMI Consultants © 2025


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>