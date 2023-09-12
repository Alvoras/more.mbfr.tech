# CTF

## Chatsubo

!!! info

	+ Source : Publication du code prévue début juillet
	+ Inspiration : [CTFd](https://github.com/CTFd/CTFd), [Hackbox](https://github.com/strellic/Hackbox), [HackTheBox](https://www.hackthebox.eu/), [TryHackMe](https://tryhackme.com)
	+ Technologies : Python, VueJS, Docker, Wireguard

La plateforme Chatsubo a été créée dans l'optique de donner la possibilité aux communautés de toutes tailles de proposer à leurs membres une plateforme d'entraînement capable d'héberger des instances vulnérables.

### Aperçu

<figure>
<center>
	<video alt="Chatsubo Demo" width="100%" controls>
	  <source src="/assets/ctf/chatsubo/media/demo.webm" type="video/webm">
	Your browser does not support the video tag.
	</video>
</center>

  <figcaption>Ajout d'une machine et connexion à l'instance</figcaption>
</figure>
<figure>
	<a href="/assets/ctf/chatsubo/media/track_boxes.png" target="_blank">
  <img src="/assets/ctf/chatsubo/media/track_boxes.png" />
  </a>
  <figcaption>Affichage des challenges de la track "Confirmé"</figcaption>
</figure>

<figure>
	<a href="/assets/ctf/chatsubo/media/users.png" target="_blank">
  <img src="/assets/ctf/chatsubo/media/users.png" />
  </a>
  <figcaption>Listing des joueurs</figcaption>
</figure>

<figure>
	<a href="/assets/ctf/chatsubo/media/box_user.png" target="_blank">
  <img src="/assets/ctf/chatsubo/media/box_user.png" />
  </a>
  <figcaption>Profil des challenges</figcaption>
</figure>

<figure>
	<a href="/assets/ctf/chatsubo/media/edit_box.png" target="_blank">
  <img src="/assets/ctf/chatsubo/media/edit_box.png" />
  </a>
  <figcaption>Interface d'édition des challenges</figcaption>
</figure>

<figure>
	<a href="/assets/ctf/chatsubo/media/submissions.png" target="_blank">
  <img src="/assets/ctf/chatsubo/media/submissions.png" />
  </a>
  <figcaption>Affichage des tentatives de validation en temps réel</figcaption>
</figure>

<figure>
	<a href="/assets/ctf/chatsubo/media/boxes_admin.png" target="_blank">
  <img src="/assets/ctf/chatsubo/media/boxes_admin.png" />
  </a>
  <figcaption>Interface d'administration des challenges</figcaption>
</figure>


!!! note
	Les captures de démo ont été réalisés avec le thème du CTF ACK&/.

### Les instances

Chaque challenge se compose de deux parties :

+ Le template, qui correspond à l'image à partir de laquelle l'instance sera déployée
+ L'instance déployée, qui expose les informations liées à son état ainsi que celles nécessaires pour communiquer avec (adresse IP, realm)

Lorsque le système de flag dynamique est utilisé, l'instance mettra également à disposition les métadonnées nécessaires pour leur validation depuis la plateforme. 

Pour l'instant, seul Docker supporte ce système grâce aux labels, qu'il est possible de récupérer via l'API et qui sont également accessible au sein du conteneur via les variables d'environnement lors de l'instanciation.  

Exemple de Dockerfile se basant sur ce système :

```Dockerfile
FROM alpine:3.12

RUN apk add python3

ARG FLAG0
ARG SESSION

LABEL chatsubo.template="hello-flag" \
        chatsubo.flags.helloworld.value="$FLAG0" \
        chatsubo.flags.helloworld.points="25" \
        chatsubo.session="$SESSION"

RUN mkdir /secrets
RUN echo "$FLAG0" > /secrets/flag
WORKDIR /secrets

CMD /bin/sh
```

Avec la ligne de commande permettant de déployer une instance à partir de ce template :

```bash
docker build . --build-arg FLAG0=level0 --build-arg SESSION=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
```

Toutes les informations exposés par les labels sont accessible depuis Chatsubo et peuvent être utilisées pour valider les flags, aiguiller les utilisateurs vers leurs instances, etc.

### Les providers

Le principe fondamental du fonctionnement du backend est le suivant : le serveur reçoit des ordres qu'il transmet aux plugins, qui savent comment l'exécuter.

Cette architecture vise à favoriser au maximum l'adaptation de Chatsubo aux différents environnements de virtualisation des communautés amenées à l'utiliser, 

Ainsi, les plugins tiennent d'une part le rôle de traducteur entre les données exposées par l'hyperviseur et celles attendues par la plateforme pour fonctionner, et d'autre part celui d'intermédiaire entre les ordres reçues depuis l'interface et la manière de les éxécutés.

Il existe aujourd'hui un plugin pour Docker et pour PVE.

Si l'on prend PVE comme exemple, il suffit de créer deux fichiers pour le rendre compatible avec Chatsubo :

+ Un fichier `provider.py` qui remplit les besoins suivants :
	+ Lister les templates disponibles
	+ Lister les instances en cours d'exécution
	+ Rollback une instance au snapshot défini comme l'état initial de la machine
	+ Créer une instance du provider à partir des données disponibles dans le fichier de configuration
+ Et un fichier `instance.py` qui traduit les informations reçues de l'hyperviseur et qui contient les données suivantes :
	+ Son nom
	+ Le `realm` dont elle fait partie
	+ Le template duquel elle est issue
	+ Son adresse IP

??? info "Afficher le code du fichier "provider.py" du plugin PVE"
	```python
	import re
	import traceback

	import requests
	from proxmoxer import ProxmoxAPI
	from urllib3.exceptions import MaxRetryError

	from app.providers.base.provider import BaseProvider
	from app.providers.base.template import BaseTemplate
	from app.providers.exc import VpnProviderNotFoundException, \
	    VpnProviderErrorException, BackendConnectionException, MetadataNotFoundException, MalformedMetadataException
	from app.providers.pve.instance import PVEInstance


	class PVEProvider(BaseProvider):
	    kind = "pve"

	    def __init__(self, name, host, user, token_name, token_value, vpns, nodes=None, verify_ssl=False, sep="--"):
	        if nodes is None:
	            nodes = ["pve"]

	        self.name = name
	        self.nodes = nodes
	        self.sep = sep
	        self.client = ProxmoxAPI(host,
	                                 user=user,
	                                 token_name=token_name,
	                                 token_value=token_value,
	                                 verify_ssl=verify_ssl
	                                 )
	        remote_nodes = [node_data["node"] for node_data in self.client.nodes.get()]
	        for node in self.nodes:
	            if node not in remote_nodes:
	                raise BackendConnectionException(f"{self.kind}/{self.name}", f"Node '{node}' not found")

	        super().__init__(kind=self.kind, vpn_confs=vpns)

	    def test_client(self):
	        nodes = self.client.nodes.get()
	        for node in nodes:
	            self.client.nodes(node["node"]).status.get()

	    def list_templates(self):
	        templates = []
	        vms = self.list_all()

	        try:
	            filtered = list(filter(lambda vm: "CHATSUBO_" in vm["description"] and vm["template"] == 1, vms))
	            rg = re.compile("CHATSUBO_TEMPLATE=(.*)")
	            for config in filtered:
	                match = rg.search(config["description"])
	                if not match:
	                    continue
	                name = match[1]
	                templates.append(BaseTemplate(name, self.to_json()).to_json())
	        except Exception:
	            raise

	        return templates

	    def list_all(self):
	        vms = []
	        for node in self.nodes:
	            try:
	                instances = self.client.nodes(node).qemu.get()
	            except (MaxRetryError, requests.exceptions.ConnectionError, ConnectionRefusedError) as e:
	                raise BackendConnectionException(f"{self.kind}/{self.name}", str(e))

	            for inst in instances:
	                inst["description"] = self.client.nodes(node).qemu(inst["vmid"]).config.get().get("description", "")
	                inst["node"] = node

	            vms += instances

	        return vms

	    def list_instances(self, realm=None):
	        instances = []
	        vms = self.list_all()
	        raw = list(filter(lambda vm: "CHATSUBO_" in vm["description"] and vm["template"] == "", vms))

	        for vm in raw:
	            try:
	                instances.append(PVEInstance(vm["vmid"], vm["name"], self.prefix, vm["description"], vm["node"], self.sep))
	            except (MetadataNotFoundException, MalformedMetadataException):
	                pass

	        if realm:
	            instances = list(filter(lambda i: i.realm == realm, instances))

	        return instances

	    def reset(self, realm, box, session=None):
	        target = None
	        instances = self.list_instances(realm=realm)
	        for inst in instances:
	            if inst.template == box.template:
	                target = inst

	        snapshots = self.client.nodes(target.node).qemu.get(f"{target.id}/snapshot")
	        last_snap_name = list(filter(lambda x: x.get("running") == 1, snapshots))[0].get("parent")

	        if not last_snap_name:
	            return False

	        self.client.nodes(target.node).qemu.post(f"{target.id}/snapshot/{last_snap_name}/rollback")
	        return True

	    @classmethod
	    def from_config(cls, name, raw_conf):
	        parsed = {
	            "name": name,
	            "host": f"{raw_conf['api']['host']}:{raw_conf['api']['port']}",
	            "user": raw_conf["api"]["user"],
	            "token_name": raw_conf["api"]["token"]["name"],
	            "token_value": raw_conf["api"]["token"]["value"],
	            "vpns": raw_conf["vpns"]
	        }

	        if nodes := raw_conf.get("nodes"):
	            parsed["nodes"] = nodes

	        if verif := raw_conf.get("verify_ssl"):
	            parsed["verify_ssl"] = verif

	        if sep := raw_conf.get("sep"):
	            parsed["sep"] = sep

	        return cls(**parsed)
	```


??? info "Afficher le code du fichier "instance.py" du plugin PVE"
	```python
	import re

	from app.providers.exc import MetadataNotFoundException, MalformedMetadataException
	from app.providers.base.instance import BaseInstance


	class PVEInstance(BaseInstance):
	    def __init__(self, id, name, prefix, description, node="pve", sep="--"):
	        self.prefix = prefix
	        self.sep = sep
	        self.node = node

	        try:
	            template, realm, address = self.parse_meta(description)
	        except (MetadataNotFoundException, MalformedMetadataException):
	            raise

	        super(PVEInstance, self).__init__(id, name, realm, template, address, sep)

	    def parse_meta(self, raw):
	        """
	        Parse and extract the template, realm and IP address from the metadata field of the instance

	        :param raw: string holding the metadata info
	        :return: returns the template name, the realm holding this instance and its IP address
	        """
	        template, realm, address = "", "", ""

	        raw = raw.lower()

	        if not any(f"chatsubo_{key}" in raw for key in ["template", "realm", "address"]):
	            raise MalformedMetadataException

	        rg = re.compile("(chatsubo_\w*)=(.*)", re.MULTILINE)
	        matches = rg.findall(raw)
	        for match in matches:
	            if match[0].replace("chatsubo_", "") == "template":
	                template = match[1]
	            elif match[0].replace("chatsubo_", "") == "realm":
	                realm = match[1]
	            elif match[0].replace("chatsubo_", "") == "address":
	                address = match[1]

	        return template, realm, address

	    def to_json(self):
	        data = self._to_json()
	        data.update({
	            "node": self.node,
	        })

	        return data
	```

Une fois le plugin créé, il suffit de renseigner les informations nécessaires dans le fichier de configuration, comme l'exemple ci-dessous :

```yaml
providers:
  pve:
    warzone: # provider name
      api:
        user: "api@pam"
        host: "https://pve.hacklab"
        port: 8006
        token:
         name: "b5215aeb-ae28-432c-b1b7-047276d87cf"
         value: "dff1ae17-4eb3-4543-a9f2-a703f375c48"
    vpns:
      - realm: "wz01"
        url: "http://gate.hacklab:7474"
        header: "X-Chatsubo-Token"
        token: "W4etxFM57y1MfRCDqzkjKfZVMEbunhoOLNE9Hj9xg7YLoZ0FXZYW8SahlGPJy6SdlRDXfDHe75x9yEZWz9TasKqG5KNPjKsSumI7KVCw28FgLnMnnbsy7jvcGvUdhGVv"
        endpoints:
          config: "/api/vpn/get/:username"
          check: "/api/check"

  docker:
  # Empty docker provider config
```

### Accès VPN

Afin de faciliter la gestion du réseau et de l'accès des joueurs aux instances, il est nécessaire de passer par un VPN pour accéder aux machines.

Les joueurs peuvent récupérer leurs accès à tout moment via l'interface web.

Pour interfacer les ponts VPN avec la plateforme, nous avons besoin d'un client dédié installé sur chacune de ces machines.

Ce client s'appelle `chatsubo-gate` et communique avec Chatsubo via une API.

Son rôle va être d'envoyer le contenu des configurations pré-générées à l'installation et de tenir une table établissant un lien entre un pseudo et une configuration VPN.

J'utilise l'image Docker [linuxserver.io](https://github.com/linuxserver/docker-wireguard) pour générer les configurations et faire tourner le serveur, mais puisque `chatsubo-gate` n'a besoin que du dossier qui contient les configurations, n'importe quelle méthode peut être utilisée.

Une configuration minimale est nécessaire pour que la plateforme et le pont VPN puisse communiquer :

+ Côté `chatsubo-gate`, il est nécessaire de renseigner le dossier contenant les fichiers de configurations, le realm ainsi que le token d'authentification utilisé pour sécuriser les échanges avec la plateforme.

```yaml
realm: "ans01"
# This token must be the same on the chatsubo plateform. "cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 128 | head -n 1" works well
chatsubo_token: "changeme_for_a_strong_and_random_token_like_128+_chars" 

wg_clients_dir: "/opt/chatsubo-gate/clients"
``` 

La notion de `realm` est importante puisqu'elle va nous permettre d'une part d'exposer plusieurs instances distinctes d'un même template en parallèle, et d'autre part de connecter plusieurs ponts VPN hébergés sur plusieurs machines différentes au même sous réseau.

+ Côté Chatsubo, il est nécessaire d'indiquer l'url du pont, le même token et le realm correspondant dans la configuration de chaque provider.

Par exemple :

```yaml
vpns:
   - realm: "ans01"
     url: "http://challs.hacklab:7474"
     header: "X-Chatsubo-Token"
	 # This token must be the same on the linked chatsubo-gate. "cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 128 | head -n 1" works well
	 chatsubo_token: "changeme_for_a_strong_and_random_token_like_128+_chars" 
     endpoints:
       config: "/api/vpn/get/:username"
       check: "/api/check"
``` 

L'en-tête utilisé pour l'authentification ainsi que les endpoints sont modifiables via la configuration de Chatsubo afin de faciliter le développement d'un connecteur alternatif dans le but, par exemple, de suporter un réseau basé sur OpenVPN.

## ACK&/

Le CTF ACK&/ était un évènement destiné exclusivement aux élèves de l'ESGI qui s'est déroulé du 19 au 21 février 2021.

Les challenges étaient conçus pour se suivre et se répartissaient sur plusieurs instances, comportant chacune 4 niveaux consécutifs.

!!! example "Exemple"
	Pour passer du level0 au level1, il fallait réussir le challenge de l'utilisateur level0 puis se connecter au suivant grâce au flag obtenu.

Deux tracks étaient disponibles :

+ La track "débutants"
	+ 12 challenges répartis en 3 instances
+ La track "confirmés"
	+ 20 challenges répartis en 5 instances

### Déploiement des instances

L'ensemble des challenges présents sur l'instance étaient installés et configurés lors du déploiement.

??? note "Exemple de Dockerfile utilisé pour déployer une instance"
	```Dockerfile
	FROM ubuntu:20.04

	# Setup
	RUN apt update
	RUN apt install -y openssh-server vim man less netcat cron zip sl

	COPY src/root/etc /etc

	# Allow caching of apt by putting it below
	# level0 password
	ARG RNG0=toor

	# Challenger's unique session, handled by Chatsubo
	ARG SESSION

	# Register all the generated flag passed by Chatsubo via --build-args
	# ENV is needed to allow entrypoint to access them
	ARG FLAG0
	ARG FLAG1
	ARG FLAG2
	ARG FLAG3

	ENV FLAGS="$FLAG0;$FLAG1;$FLAG2;$FLAG3"
	RUN echo $FLAGS

	RUN useradd -ms /bin/bash -p $(openssl passwd -6 "$RNG0") level0
	RUN useradd -ms /bin/bash -p $(openssl passwd -6 "$FLAG0") level1
	RUN useradd -ms /bin/bash -p $(openssl passwd -6 "$FLAG1") level2
	RUN useradd -ms /bin/bash -p $(openssl passwd -6 "$FLAG2") level3
	RUN useradd -ms /bin/bash -p $(openssl passwd -6 "$FLAG3") level4

	# Exposed metadata, needed by Chatsubo for dynamic flags, session handling and ssh initial access
	LABEL chatsubo.template="adv_ans01" \
	        chatsubo.creds.ssh.username="level0" \
	        chatsubo.creds.ssh.password="$RNG0" \
	        chatsubo.flags.step0.value="$FLAG0" \
	        chatsubo.flags.step0.points="250" \
	        chatsubo.flags.step1.value="$FLAG1" \
	        chatsubo.flags.step1.points="250" \
	        chatsubo.flags.step2.value="$FLAG2" \
	        chatsubo.flags.step2.points="250" \
	        chatsubo.flags.step3.value="$FLAG3" \
	        chatsubo.flags.step3.points="250" \
	        chatsubo.session="$SESSION"

	# Add challenges setup scripts and resources
	COPY src/root /
	RUN chmod u+x /home/level**/ans_init.sh

	# Needed for sshd
	RUN mkdir /run/sshd

	RUN echo "$FLAGS" > /root/flags

	COPY src/entrypoint.sh /entrypoint.sh
	RUN chmod u+x /entrypoint.sh

	ENTRYPOINT /bin/bash -c '/etc/init.d/cron start && cat /root/flags | /entrypoint.sh'

	```

Chaque dossier comprenait un Dockerfile comme celui ci-dessus ainsi que l'ensemble des fichiers à copier dans le conteneur.

Par exemple :

```
.
|-- Dockerfile
|-- Makefile
`-- src
    |-- entrypoint.sh
    `-- root
        |-- etc
        |   `-- ssh
        |       `-- sshd_config
        `-- home
            |-- level0
            |   |-- ans_init.sh
            |   `-- main.c
            |-- level1
            |   |-- ans_init.sh
            |   `-- hexhexhex
            |-- level2
            |   |-- ans_init.sh
            |   |-- challenge.py
            |   `-- create_flag.py
            |-- level3
            |   |-- ans_init.sh
            |   |-- main.c
            |   `-- patch.py
            `-- level4
                |-- ans_init.sh
                `-- finish.txt
```

L'entrypoint avait pour seul rôle d'appeler le script `ans_init.sh` présent dans le home de chacun des utilisateurs, en lui transmettant le flag à insérer dans le challenge, le nom de l'utilisateur courant ainsi que celui du suivant :

```bash
#!/bin/bash

rm -f $0

SCRIPT_NAME="ans_init.sh"
RAW_FLAGS="$(cat /root/flags)"
FLAGS=(${RAW_FLAGS//;/ })

# Start challenge setup script for each levels and remove it
for i in {0..4}; do
  current_user="level$i"
  next_user="level$(($i + 1))"
  init_script="/home/level$i/$SCRIPT_NAME"
  current_flag=${FLAGS[i]:-"_"}
  [ -f "$init_script" ] && bash -c "$init_script $current_flag $current_user $next_user"
  rm -f $init_script
done

rm -f /root/flags

/etc/init.d/cron start

# Allow remote access
while true; do
  /usr/sbin/sshd -e -D
done

```

Ce script, `ans_init.sh`, était écrit par le créateur du challenge et s'occupait de mettre en place les différents éléments nécessaires à son fonctionnement :

```bash
FLAG=$1            
CURRENT_USER=$2
NEXT_USER=$3
bin_name="hexhexhex"

chown -R "$CURRENT_USER:" "/home/$CURRENT_USER"
chown "$NEXT_USER:" "/home/$CURRENT_USER/$bin_name"
chmod u+xs "/home/$CURRENT_USER/$bin_name"

echo $FLAG > "/home/$NEXT_USER/flag"
chown "$NEXT_USER:" "/home/$NEXT_USER/flag"
chmod 400 "/home/$NEXT_USER/flag"
```

## Challenges
### Dimensional

Ce challenge a été diffusé lors du CTF ACK&/ organisé par le Hacklab ESGI. 

Il s'agit d'une *text adventure* auquelle il faut tricher pour obtenir un objet précis ainsi qu'un mot de passe, qui permettent au joueur de se rendre dans le cyberespace et d'y de récupérer le flag.

#### TL;PL

1) Lire la note sur le bureau pour comprendre l'objectif : aller dans le cyberespace grâce à l'item UVL540, chargé depuis la console

2) Trouver la console qui nécessite un mot de passe

3) Faire le tour du jeu pour comprendre qu'il faut obtenir l'UVL540 en trichant

4) Décompresser le fichier de sauvegarde pour le rendre lisible

5) Analyser le format de la sauvegarde pour identifier sa structure

6) Identifier comment générer le check d'intégrité (`sha512(save)[12:]`) en analysant les paquets importés par le binaire via `strings`

7) Itérer sur les identifiants des items, séquentiels, jusqu'à obtenir l'UVL540 (ID 4)

8) Trouver le dialogue caché grâce à `strings` pour identifier le \*clavier\* et récupérer ainsi le mot de passe de la console caché dessous

9) Charger l'UVL540 pour aller dans le cyberespace et obtenir le flag

#### Premiers pas

Nous lançons le binaire une première fois :

![](https://i.imgur.com/OViXUKw.png)

Il s'agit d'une text adventure, qui fonctionne de la manière suivante : 

+ Les \*astérisques\* indiquent les *endroits* où nous pouvons nous déplacer
+ Les [crochets] indiquent les objets avec lesquels nous pouvons interagir
+ Nous pouvons faire une sauvegarde grâce à la commande save

Nous allons au bureau et nous lisons la note :

```
Un mot est écrit sur la note :
        Salut alvoras,
        J't'avais bien dit que j'allais réussir.
        Un moyen de transcender la matière, de communiquer à la vitesse de la lumière. Bordel si ça donne pas envie ça !
        Si un jour tu lis ce message, démerde-toi pour récupèrer un [UVL540] et charge le programme de saut depuis la [console], dans la pièce d'à côté.
        Puis rejoins-moi dans le *cyberespace*.
                - Moc
```

Plusieurs informations importantes ici :

+ Nous devons obtenir un UVL540, qui est un objet utilisable
+ Nous devons trouver la console pour charger le programme de saut
+ Puis nous devons nous rendre dans la salle "cyberespace"

Nous pouvons tenter de nous rendre directement dans le cyberespace : 
![](https://i.imgur.com/By7s0yL.png)


... qui nous accueille en nous grillant la cervelle puisque nous ne possédons pas d'UVL540.

En relançant le jeu, nous remarquons que la sauvegarde a été supprimée.

Nous continuons à découvrir le jeu en allant vers la porte, indiquée au début du jeu. 

![](https://i.imgur.com/80LDKcE.png)

Nous découvrons la prochaine salle, la "Salle de saut", et nous déverrouillons la porte grâce à la clef située au dessus de la porte.

Nous pouvons consulter notre inventaire avec la commande `inv` :

![](https://i.imgur.com/EY1pMyM.png)

Une fois dans la salle de saut, nous trouvons la `console`, dont nous avons besoin pour charger l'UVL540 avant de pouvoir nous rendre dans le cyberespace.

Nous tentons d'utiliser la console : 

![](https://i.imgur.com/b9ySTB6.png)

Il nous faut donc un mot de passe... et notre sauvegarde est une nouvelle fois supprimée si nous nous trompons.

Nous continuons à fouiller, mais nous avons bel et bien fait le tour du jeu.

#### Analyse

Récapitulons :
+ Le but du jeu est de nous rendre dans le cyberespace 
+ Pour cela, nous avons besoin de l'item "UVL540"
+ Il faut que cet item soit "chargé" via la console
+ La console demande un mot de passe

Nous avons donc besoin :
1) D'obtenir un objet qui ne peut pas être obtenu dans le jeu
2) Du mot de passe de la console

Il va falloir tricher !

#### UVL540
##### Le format de sauvegarde
Commençons par analyser une sauvegarde toute fraîche :

![](https://i.imgur.com/pdcPQi7.png)

Il s'agit donc d'un fichier compréssé gzip contenant une chaîne de caractère.

Nous obtenons le format suivant :
```
nom::position::12 caractères hexa
```

Nous avons le nom du joueur, la pièce dans laquelle nous nous trouvons et 12 caractères en hexadécimal, à priori sans lien avec le jeu. Le séparateur semble être "::".

Nous rechargeons la sauvegarde et avançons dans le jeu pour voir comment sa structure évolue : 

![](https://i.imgur.com/b0K2iwl.png)

Nous remarquons que le jeu affiche l'état de la sauvegarde lorsque nous la chargeons et que la valeur correspond au dernier champ du fichier de sauvegarde.

Ici, nous nous sommes déplacés et avons ajouté deux objets à notre inventaire : la boîte et la clef, dont nous avons fait passer l'état à "used".

![](https://i.imgur.com/SK01eSu.png)

La sauvegarde ressemble maintenant à : 
![](https://i.imgur.com/nBhaWEh.png)

!!!info
	Note : Un retour à la ligne a été ajouté à la fin de la commande (`&& echo`) pour que la sauvegarde soit lisible. Le fichier de sauvegarde est considéré comme corrompu par le jeu s'il se termine par un saut de ligne.

Nous retrouvons 2 blocs au format `<int>;<string>` au premier `::` et le nom d'une salle au second `::`.

Nous comprenons qu'il s'agit de l'inventaire avec une suite d'objets sous la forme `<id>;<état>,` puisque l'on retrouve l'état "used" de notre clef. On note au passage que la case d'état peut être vide (`2;<null>`).

Les 12 caractères ont changés avec la sauvegarde, il s'agit donc certainement d'un hash (type MD5) ou d'un code de correction d'erreur (type CRC32).

Le format de la sauvegarde est donc le suivant : 
```
<nom>:<objet1>;<état>,<objet2>;<état>,...,<objetN>;<état>:<position>:<position précédente>:<checksum>
```

Les identifiants des objets semblent être incrémentaux : nous testons de changer notre clef en boîte (deux objets dont l'ID est connu) en changeant l'ID de l'item `1` en `2`.

Pour cela nous décompressons notre fichier de sauvegarde avec `zlib-flate -uncompress < ./.save.ans > save.uncomp`, que nous recompressons avec `zlib-flate -compress < ./save.uncomp > .save.ans`.

!!!danger
	Important : il est nécessaire d'utiliser `set noendofline binary` à chaque ouverture de vim ou d'inscrire ce paramètre dans un fichier `.vimrc` à la racine du dossier pour éviter que vim ne rajoute de saut de ligne à la fin du fichier et ne corrompe la sauvegarde.

	Une alternative serait de recréer un fichier intermédiaire en retirant le retour à la ligne avec `head -c -1 ./save.uncomp > ./save.uncomp2`.

Nous forgeons la nouvelle sauvegarde et tentons de la charger : 

![](https://i.imgur.com/CRzJ8hY.png)

Le jeu nous indique que notre sauvegarde est corrompue.

##### Le check d'intégrité

Nous voulons vérifier si l'hypothèse du check d'intégrité est juste. Pour cela, nous allons chercher dans le binaire si des fonctions de hachage sont utilisées.

Il n'est pas nécessaire de sortir un logiciel de reverse comme IDA pour l'instant ; nous commencerons par utiliser les commandes `file` et `strings`.

Le `file` nous indique qu'il s'agit d'un binaire 64 bits codé en Go, non strippé : 
```
level0@359b243ce4cd:~$ file ./dimensional 
./dimensional: setuid, setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=KRbhNK-qTCrI6YYoim48/mbevmsH8s-itlC7_D9zy/GKbmbssdYECvm3tn7IoT/HS2lESc5tiP-_ekaKQ5m, not stripped
```

Les programmes compilés depuis le Golang conservent l'ensemble des fonctions utilisés en clair dans le code source. Nous confirmons cela avec un premier `strings` sans filtre :
```
level0@359b243ce4cd:~$ strings ./dimensional
...
gitlab.com/Alvoras/dimensional/internal/game.UserInputln
gitlab.com/Alvoras/dimensional/internal/game.PasswordInputln
gitlab.com/Alvoras/dimensional/internal/game.init.0.func1
gitlab.com/Alvoras/dimensional/internal/game.init.0.func2
gitlab.com/Alvoras/dimensional/internal/game.init.0.func3
gitlab.com/Alvoras/dimensional/internal/game.init.0.func4
gitlab.com/Alvoras/dimensional/internal/game.init.0.func5
gitlab.com/Alvoras/dimensional/internal/game.init.0.func6
gitlab.com/Alvoras/dimensional/internal/game.init.0.func7
gitlab.com/Alvoras/dimensional/internal/game.init.0.func8
type..eq.gitlab.com/Alvoras/dimensional/internal/game.SaveItem
type..eq.[5]interface {}
main.main
```

En utilisant `grep`, nous pouvons isoler les fonctions potentiellement utilisées grâce aux noms des paquets correspondants :

+ "hash"

```
level0@359b243ce4cd:~$ strings ./dimensional | grep -i hash/
hash/adler32
hash/adler32.(*digest).Reset
hash/adler32.(*digest).Size
hash/adler32.(*digest).BlockSize
hash/adler32.update
hash/adler32.(*digest).Write
hash/adler32.(*digest).Sum32
hash/adler32.(*digest).Sum
hash/adler32.New
hash/adler32.Checksum
/usr/local/go/src/hash/adler32/adler32.go
hash/adler32..inittask
go.itab.*hash/adler32.digest,hash.Hash32
hash/adler32.(*digest).Reset
hash/adler32.(*digest).Size
hash/adler32.(*digest).BlockSize
hash/adler32.update
hash/adler32.(*digest).Write
hash/adler32.(*digest).Sum32
hash/adler32.(*digest).Sum
```

+ "crypto"

```
level0@359b243ce4cd:~$ strings ./dimensional | grep -i crypto/
crypto/sha512
crypto/sha512.init.0
crypto/sha512.(*digest).Reset
crypto/sha512.New
crypto/sha512.New512_224
crypto/sha512.New512_256
crypto/sha512.New384
crypto/sha512.(*digest).Size
crypto/sha512.(*digest).BlockSize
crypto/sha512.(*digest).Write
crypto/sha512.(*digest).Sum
crypto/sha512.(*digest).checkSum
crypto/sha512.Sum512
crypto/sha512.block
crypto/sha512.init
crypto/sha512.blockAMD64
crypto/sha512.blockAVX2
/usr/local/go/src/crypto/sha512/sha512block_amd64.s
/usr/local/go/src/crypto/sha512/sha512block_amd64.go
/usr/local/go/src/crypto/sha512/sha512.go
/usr/local/go/src/crypto/crypto.go
crypto/sha512.blockAVX2.args_stackmap
crypto/sha512.blockAMD64.args_stackmap
crypto/sha512..inittask
crypto/sha512._K
crypto/sha512.useAVX2
go.itab.*crypto/sha512.digest,hash.Hash
crypto/sha512.init.0
crypto/sha512.(*digest).Reset
crypto/sha512.New
crypto/sha512.New512_224
crypto/sha512.New512_256
crypto/sha512.New384
crypto/sha512.(*digest).Size
crypto/sha512.(*digest).BlockSize
crypto/sha512.(*digest).Write
crypto/sha512.(*digest).Sum
crypto/sha512.(*digest).checkSum
crypto/sha512.Sum512
crypto/sha512.block
crypto/sha512.init
crypto/sha512.blockAMD64
crypto/sha512.blockAVX2
```

Nous identifions quatre candidats : 

+ Adler32
+ SHA512-224
+ SHA512-256
+ SHA384
+ SHA512

L'algorithme Adler32 ne produit que des sommes, exprimées en un nombre possédant jusqu'à 10 chiffres ; nous l'écartons donc pour nous concentrer sur le SHA-512.

!!!info
	L'algorithme Adler32 est utilisé par la compression gzip, ce qui justifie sa présence dans le binaire.

Puisqu'il existe 3 formats gérés par la lib crypto/sha512, nous nous contenterons... de tous les essayer.

Ces fonctions correspondent aux algorithmes 512-224, 512-256, 384, et 512  de la commande `shasum`. Nous pouvons donc toutes les tester de la manière suivante : 

```
level0@359b243ce4cd:~$ echo -n "alvoras:1;used,2;:Salle de saut:Porte:" > ./raw

level0@359b243ce4cd:~$ shasum -a 512224 ./raw; shasum -a 512256 ./raw; shasum -a 384 ./raw; shasum -a 512 ./raw
9a8632699d0e944ef4733d84468878561f2491414db301287f341eaa  ./raw
ca3e64ee4b2fd78d393c99952207bf09c6d95bc4759e3154a3d68cf301c9fd0b  ./raw
abe6d7fcbfc0bc8536b6b8b62a9f9596d6c8024bba450541ef58c9ad6595e84f8d367b08be84746a7fb5c67ec920965f  ./raw
4937897b1ad44ed355e8324d3d9a67fe7ff80cfc16101c6aabe54dbb3059a36900e526c3a750b885cd22ae26412a81a075d77ed82036a3b3f38271772c497bf0  ./raw
```

Nous avons un match avec la dernière commande : il s'agit donc des 12 premiers caractères d'un SHA512 du fichier de sauvegarde.

Nous validons notre hypothèse en reprenant la manipulation citée plus haut mais en modifiant cette fois-ci le hash : 

```
level0@359b243ce4cd:~$ echo -n "alvoras:2;used,2;:Salle de saut:Porte:" | sha512sum | head -c 12 && echo
88038a66346d
level0@359b243ce4cd:~$ # On modifie l'ID de la clef et on remplace le hash tronqué 
level0@359b243ce4cd:~$ vim ./save.uncomp  
level0@359b243ce4cd:~$ zlib-flate -compress < ./save.uncomp > .save.ans
```

![](https://i.imgur.com/Tl08Sml.png)

Notre sauvegarde est valide et nous obtenons bien deux boîtes dans notre inventaire.

##### La génération d'objets

Maintenant que nous sommes en mesure de modifier la sauvegarde sans la corrompre, nous pouvons faire apparaître n'importe quel item dans notre inventaire.

Nous ne connaissons pas l'ID de l'UVL540. Qu'à cela ne tienne, nous générons les items possédant les IDs de 1 à 30.

Pour simplifier les manipulations, nous créons un petit script bash qui reprend les commandes au-dessus : 

```bash
save="alvoras:1;used,2;,3;,4;,5;,6;,7;,8;,9;,10;,11;,12;,13;,14;,15;,16;,17;,18;,19;,20;,21;,22;,23;,24;,25;,26;,27;,28;,29;,30;:Salle de saut:Porte:"
hash=$(echo -n "$save" | sha512sum | head -c 12)

echo $save$hash
echo -n $save$hash > tmp_save
zlib-flate -compress < ./tmp_save > .save.ans
./dimensional
```

... et nous obtenons une sauvegarde corrompue.

Nous vérifions que le script fonctionne bien en ajoutant un unique objet : 

```bash
save="alvoras:1;used,2;,3;:Salle de saut:Porte:"
hash=$(echo -n "$save" | sha512sum | head -c 12)

echo $save$hash
echo -n $save$hash > tmp_save
zlib-flate -compress < ./tmp_save > .save.ans
./dimensional
```

![](https://i.imgur.com/s4Wu5WR.png)

Il fonctionne donc correctement ; le crash peut être lié soit à une trop grande quantité d'objets dans l'inventaire, soit à des identifiants invalides.

Nous avançons plus prudemment en itérant sur le 3ème champ, jusqu'à arriver sur la sauvegarde suivante : 

`alvoras:1;used,2;,4;:Salle de saut:Porte:7dc79aa29c6f`

![](https://i.imgur.com/g8yLGQu.png)

Nous obtenons ainsi l'UVL540, qui possède l'identifiant "4".

#### La console

Une fois l'UVL540 obtenu, il faut aller charger le programme de saut depuis la console. Un mot de passe est nécessaire, sans quoi la sauvegarde est détruite.

Encore une fois, nous utilisons `strings` pour fouiller dans le programme.

Nous cherchons une chaîne de caractère que nous savons présente (ici "Si un jour tu lis ce message,") pour nous rendre dans la section où sont contenues les variables du programme :

![](https://i.imgur.com/P7fjm8t.png)

Quelques lignes de dialogue que nous n'avons jamais vu attire notre attention :

``` 
> Tu cherches des indices autour de toi.
> Le vieux avait une mauvaise m
moire, le mot de passe devrait 
tre not
 quelque part...
> Bingo ! Sous le *clavier*. Si l'ANSSI voyait 
a...
```

Dans la salle de saut, nous nous rendons devant le \*clavier\*...

![](https://i.imgur.com/POSjEVM.png)

... pour y trouver le mot de passe.

!!!info
	Pour éviter que le mot de passe ne se retrouve en clair dans le binaire et forcer le joueur à passer par le jeu, il est dérivé de manière dynamique à partir du hash d'intégrité de la sauvegarde chargée.

Nous le rentrons dans la console :

![](https://i.imgur.com/pdsvGqE.png)

L'UVL540 est maintenant chargé.

![](https://i.imgur.com/MqAgaV4.png)

#### Le flag

Nous pouvons désormais utiliser l'item pour se rendre dans le cyberespace et récupérer le flag : 

![](https://i.imgur.com/nBU64TM.png)
