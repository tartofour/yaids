<h1 align="center">
  <a href="https://github.com/tartofour/yaids"><img src="https://cdn.freebiesupply.com/logos/large/2x/c-2975-logo-png-transparent.png" alt="Yaids" width="200"></a>
  <br>
  Projet de développement : Yaids (Yet Another IDS)
  <br>
  <br>
</h1>


## Table des Matières

- Démarrage rapide
    - [Dépendances](#d%C3%A9pendances)
    - [Installation](#installation)
    - [Utilisation](#utilisation)
    - [Protocoles pris en charge](#protocoles-pris-en-charge)
    - [Options de règles](#options-de-règles)
- Documentation du code source
    - [main.c](#main.c)
    - [populate.c](#populate.c)
    - [populate.h](#populate.h)
    
# Démarrage rapide
## Dépendances

Afin d'être en mesure de compiler le code source, le packet `libcap-dev` doit être installé sur la machine hôte.  
Pour install lib-cap:

```bash
# apt update && apt install -y libcap-dev
```

## Installation

La façon la plus facile d'installer yaids est de cloner ce dépôt et de compiler le code source à l'aide du fichier Makefile.  
Pour ce faire, exécutez les commandes suivantes depuis le terminal:

```
$ git clone https://github.com/tartofour/yaids.git
$ cd yaids
$ make
```

### Intégration au système GNU/Linux

Pour ajouter automatiquement `yaids` dans le dossier `/usr/local/bin/` et pour l'intégrer à systemd, executez le script d'installation en temps qu'administrateur:

```
# ./install.sh
```

## Désinstallation

Pour désinstaller yaids, executez le script de désinstallation en temps qu'administrateur:

```
# ./uninstall.sh
```

## Utilisation

Afin d'executer `yaids`, il est indispensable de lui fournir un fichier de règles.  
Il est également recommandé de spécifier une interface d'écoute :

```
# yaids <rules_file> [interface]
```

## Protocoles pris en charge

Permet de définir le protocole sur lequel s'applique la règle. `yaids` prend en charge les protocoles suivants:
- `TCP`
- `UDP`
- `ICMP`
- `HTTP`
- `FTP`
- `SSH`

## Options de règles
Yaids prend en charge deux type d'options :
- `content` qui permet de rechercher une chaine de caractère dans le payload d'un paquet.
- `msg` qui permet de définir la chaine de caractère à écrire dans le journal du système lors d'un match. 

# Documentation du code source
## main.c
### void print_help(char * prg_name);

Argument : 
- char * prg_name : Nom du programme

Description : 
- Affiche le menu d'aide.

### void print_error(char * err_str)
Argument : 
- char * err_str: Chaine de caractère à afficher à l'écran

Description :
- Affiche un message d'erreur.

### void print_rules(Rule *rules, int count)
Argument : 
- Rule *rules : Tableau d'instances rules.
- int count : Nombre d'instances rules dans le tableau.

Description :
- Affiche un résumé des règles présentes dans le tableau de règles.
* * *

### void remove_char_from_str(char *new_str, char *str, char char_to_remove)
- Copie une chaine de caractère en retirant le caractère entré en paramètre.
* * *

### bool is_action_in_rule_valid(char *action_str)
- Vérifie la validité de la valeur présente dans le champ `action` pour une règle.
* * *

#### bool is_protocol_in_rules_valid(char *protocol)
- Vérifie la validité de la valeur présente dans le champ `protocole` d'une règle.
* * *

#### bool is_ip_in_rules_valid(char *ip)
- Vérifie la validité de la valeur présente dans le champs `ip` d'une règle.
* * *

### bool is_port_in_rules_valid(char *port)
- Vérifie la validité de la valeur présente dans le champ `port` d'une règle.
* * *

### bool is_direction_in_rules_valid(char *direction)
- Vérifie la validité de la valeur présente dans le champ `direction` d'une règle.
* * *





## Licence

[MIT](/usr/share/joplin/resources/app.asar/LICENSE "LICENSE"). Copyright (c) Jonathan Rasque & Benjamin Verjus
