# FGR Mail SMTP

Ein WordPress-Plugin der [Freien Gestalterischen Republik](https://fgr.design).

Ersetzt den Standard-WordPress-Mailer und sendet alle ausgehenden E-Mails über einen eigenen SMTP-Mailserver — zuverlässig, verschlüsselt und vollständig im WordPress-Backend konfigurierbar.

## Funktionen

- SMTP-Unterstützung für jeden Mailserver (Strato, 1&1, eigener Server u.v.m.)
- Verschlüsselung: TLS, SSL oder ohne
- SMTP-Authentifizierung mit Benutzername und Passwort
- Passwort wird verschlüsselt in der Datenbank gespeichert (AES-256)
- Automatische Port-Vorschläge je nach gewählter Verschlüsselung
- Eigene Absenderadresse und Absendername einstellbar
- Testmail-Funktion direkt im WordPress-Backend
- Automatische Update-Benachrichtigungen über GitHub

## Installation

1. [Neueste Version herunterladen](https://github.com/FreieGestalterischeRepublik/fgr-mail-smtp/releases/latest)
2. Im WordPress-Backend unter **Plugins → Installieren → Plugin hochladen** die ZIP-Datei hochladen
3. Plugin aktivieren
4. Unter **Einstellungen → FGR Mail SMTP** den Mailserver konfigurieren

## Konfiguration

| Feld | Beschreibung |
|------|--------------|
| SMTP-Host | Adresse des Mailservers (z.B. `mail.example.com`) |
| SMTP-Port | 587 (TLS), 465 (SSL), 25 (ohne) |
| Verschlüsselung | TLS, SSL oder keine |
| Benutzername | E-Mail-Adresse oder Benutzername beim Mailserver |
| Passwort | Wird verschlüsselt gespeichert |
| Absender-E-Mail | Absenderadresse für alle WordPress-E-Mails |
| Absender-Name | Angezeigter Name beim Empfänger |

## Voraussetzungen

- WordPress 6.0 oder höher
- PHP 8.0 oder höher

## Lizenz

GPL-2.0-or-later — siehe [LICENSE](LICENSE)
