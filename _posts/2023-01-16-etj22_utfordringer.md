---
title: Etjenesten22 - Utfordringer
date: 2023-01-16 10:30:00 +0100
categories: [Etjenesten, Etjenesten Jul 22]
tags: [ctf, etjenesten, "2022", "kontroll-13", assembly, norwegian]
media_subpath: /assets/img/etjenesten22/
---
# 3.2. Utfordringer middels
Jeg gjorde middels-utfordringer for `kontroll-13`, som er et custom språk som minner om assembly, med eget instruksjonssett.
Programmet må "bygges" (kompileres), og består av et data-segment som definerer variabler, og et instruksjons-segment som er selve instruksjonene. Disse er skilt med en linje av `=`, hvor den øverste delen er data-segmentet, og det nederste er instruksjons-segmentet.

# 3.2.1.01_rtfm
```
Skriv et program som skriver ut teksten "Hello, world!" (ett ord per tegn).
```
```
:tekst .DATA 0x48 0x65 0x6c 0x6c 0x6f 0x2c 0x20 0x77 0x6f
       .DATA 0x72 0x6c 0x64 0x21 0x00 ; "Hello, world!"
==========================================================
.ALIAS  neste   0xff
FINNE   tekst

:løkke
LASTE neste
FORBI /NULL 0
HOPPE ferdig
UT neste
HOPPE løkke

:ferdig
STOPPE 0
```

# 3.2.1.02_sum-of-all-fears
```
Skriv et program som leser inn to tallverdier og skriver ut summen av dem (1 ord på 13 bit).
```
```
:a    .DATA 0
:b    .DATA 0
=================
INN   a
INN   b

:løkke
    PLUSSE a b
    UT a

:ferdig
    STOPPE  0
```

# 3.2.1.03_it-compares
```
Skriv et program som leser inn to tallverdier A og B og skriver ut enten tallverdien 1 hvis A er større enn B, eller 0 i alle andre tilfeller.
```
```
:null .DATA 0
:en   .DATA 1
:a    .DATA 0
:b    .DATA 0
======================
INN   a
INN   b

:løkke
    MINUSE b a
    FORBI /MENTE 0
    HOPPE astor
    HOPPE bstor

:astor
    UT en
    HOPPE ferdig

:bstor
    UT null
    HOPPE ferdig

:ferdig
    STOPPE  0
```

# 3.2.1.04_encryption
```
Skriv et program som leser inn en nullterminert ASCII-streng (1 ord per tegn), tar ENTEN (XOR) av hvert tegn med 0x1b39 og skriver ut resultatet.
```
```
:key .DATA 0x1b39
:tekst
=========================
:løkke
    INN     tekst
    FORBI   /NULL   0
    HOPPE   ferdig
    ENTEN   tekst key
    UT tekst
    HOPPE løkke

:ferdig
    STOPPE 0
```

# 3.2.1.05_decryption
```
Skriv et program som leser inn:
  1. Mengden data som skal dekrypteres (1 ord), deretter
  2. Selve de krypterte dataene.
Programmet skal ta ENTEN (XOR) av dataene med 4919 og skrive ut resultatet.
```
```
:key .DATA 4919
:en  .DATA 1
:lengde .DATA 0
:tekst
=========================
INN lengde

:løkke
    FORBI   /NULL 0
    STOPPE 0
    INN     tekst
    ENTEN   tekst key
    UT tekst
    MINUSE lengde en
    HOPPE løkke
```


# 3.2.1.06_calculator + 3.2.1.07_fastulator
Disse oppgavene har samme løsningen. Hver instruksjon tar èn syklus.

### 3.2.1.06_calculator
```
Skriv et program som evaluerer et regnestykke og skriver resultatet til utstrømmen.
  - Regnestykket er på formen 10 + 5 - 3 * 4 / 2 =, hvor hvert ord i inputen er enten et tall eller en operator.
  - Operatorene er ASCII-tegn.
  - Regnestykket skal evalueres fra venstre mot høyre, slik at svaret på regnestykket i eksemplet skal bli 24.
  - Operatorene er +, -, *, / og =.
  - Programmet skal skrive ut resultatet når operatoren er = og så stoppe med feilkode 0.
  - Hvis man forsøker å dele på 0 skal programmet stoppe med feilkode 1 uten å skrive ut noe.
  - Hvis operatoren er ugyldig skal programmet stoppe med feilkode 2 uten å skrive ut noe.
```
### 3.2.1.07_fastulator
```
Skriv en optimalisert utgave av programmet fra forrige oppgave ("calculator").

For å bestå denne oppgaven må programmet ditt være effektivt nok til å løse alle testene på det tilmålte antallet sykluser. For øvrig er kravene de samme som i forrige oppgave.
```

### Løsningen
Løsningen er basert på at vi sjekker èn og èn operasjon, og hvis den første operasjonen vi sjekker for ikke stemmer, så går vi videre til neste.
```
:tall .DATA 0
:operator .DATA 0
:res .DATA 0
=====================================
INN res
HOPPE løkke

:ikke_pluss
  FORBI /RESULTAT 0x2a
  HOPPE ikke_pluss_gange
  INN tall
  GANGE res tall

:løkke
  INN operator

  FORBI /RESULTAT 0x2b
  HOPPE ikke_pluss
  INN tall
  PLUSSE res tall
  HOPPE løkke

:ikke_pluss_gange
  FORBI /RESULTAT 0x2d
  HOPPE ikke_pluss_gange_minus
  INN tall
  MINUSE res tall
  HOPPE løkke

:ikke_pluss_gange_minus
  FORBI /RESULTAT 0x2f
  HOPPE ikke_pluss_gange_minus_dele
  INN tall
  FORBI /NULL 0
  STOPPE 1
  DELE res tall
  HOPPE løkke

:ikke_pluss_gange_minus_dele
  FORBI /RESULTAT 0x3d
  STOPPE 2
  UT res
  STOPPE 0
```
