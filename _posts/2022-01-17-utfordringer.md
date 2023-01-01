---
title: Etjenesten21 - Utfordringer
date: 2022-01-17 14:00:00 +0100
categories: [Etjenesten, Etjenesten Jul 21]
tags: [ctf, etjenesten, rev, xor, crypto, vernam, python, spektrogram, NO]
img_path: /assets/img/etjenesten21/
---
# 3.1.1_PKrypt
Vi får et flagg som er kryptert, og vi får krypteringsfunksjonen som er brukt på flagget.
Siden denne oppgaven var gradert "lett" gjettet jeg at krypteringen kanskje var en enkel xor med en key. Det viste seg å stemme. Ut ifra flaggfilen kan vi se at flagget er 46 bytes.

Siden PKrypt programmet bruker xor med en key for å kryptere kan vi finne denne keyen igjen med å xor-e plaintext og ciphertext. Vi sender 46 'A'-er inn til PKrypt, og tar XOR mellom plaintexten ('A'ene) og cipherteksten som kom ut.
Vi får da keyen (i hexadecimal):
`35323936383939353737333632323539393431333839313234393732313737353238333437393133313531353537`

Siden krypteringsmåten er XOR, så kan vi XOR-e keyen med det krypterte flagget for å få ut det dekrypterte flagget;

`65746a7b6c796b6b656c69675f65725f64656e5f736f6d5f7665745f73697374655f7369666665725f695f70697d`

Som er hexadecimal for:
`etj{lykkelig_er_den_som_vet_siste_siffer_i_pi}`


# 3.2.2_lydnøtter
Vi får utdelt en lydfil. Når man spiller av denne lydfilen hintes det veldig mye til spekteret, etterfulgt av mye summing.

Vi kan se spekteret til mp3-fila med f-eks Audacity. Det vil da se slik ut:

![spekter](spekter.png)

Vi kan se teksten `GZNJVPRHUMVJIFFE`, dette er ciphertekst, og hvis man prøver å submitte det som et flagg får man responsen `Dette ser ut som en ciphertext, kanskje det finnes en nøkkel et sted`.

Hvis man ser litt nøyere etter på bildet kan man se noe som ligner morsekode. Hvis man gjør om denne morsekoden til tekst får man `NOEKKEL ER BONDPASSFILTER BRUK NORSK ALFABET`.

Vi har dermed cipherteksten og nøkkelen, så da gjenstår det bare å finne ut hvordan man bruker nøkkelen.

Det viser seg at dette er noe som heter *Vernam Cipher*. For å dekode dette cipheret konverterer man bokstavene i cipherteksten, og keyen, om til nummeret deres i alfabetet (A=0,B=1...Å=28), og tar `(Cipher_nummer - Key_nummer) mod 29`

Man får da flagget `FLAGGPÅSPEKTERET`


# 3.3.2_guessing_game_1
Scriptet sender inn alle tallene mellom en range lower_range og upper_range.

```python
import requests
import math

NUMBERS = 64
GUESSES = 6
LIES = 0

ENDPOINT = "http://guessing-game"

def ask_question(game_id, question):
    response = requests.post(
        f"{ENDPOINT}/ask_question", json={"game_id": game_id, "question": question}
    )
    return response.json()["answer"]

def start_game():
    response = requests.post(f"{ENDPOINT}/start_game", json={"N": NUMBERS, "M": GUESSES, "K": LIES})
    return response.text

def verify_guess(game_id, guess):
    response = requests.post(
        f"{ENDPOINT}/verify_guess", json={"game_id": game_id, "guess": guess}
    )
    try:
        print(response.json()["flag"])
    except Exception:
        pass
    return response.json()["correct"], response.json()["secret_number"]

def generate_list(lower, upper):
    ls = []
    for i in range(lower, upper+1):
        ls.append(i)
    return ls

def run_example_solver():
    game_id = start_game()

    # Binary search our way down until there is only
    # one possibility left
    lower_range = 1
    upper_range = NUMBERS
    for _ in range(GUESSES):
        mid = math.floor((lower_range + upper_range)/2)
        valid_numbers = generate_list(lower_range, mid)
        answer = ask_question(game_id, valid_numbers)
        if answer == 1:
            upper_range = mid
        elif answer == 0:
            lower_range = mid+1
        guess = upper_range

    # Make guess
    correct, secret_number = verify_guess(game_id, guess)
    print(
        f"Guessed {guess} and was {'' if correct else 'in'}correct - answer is {secret_number}"
    )


if __name__ == '__main__':
    run_example_solver()
```


# 3.3.3_guessing_game_2
Denne krever manuell skrivning av lower_range og upper_range for hvert guess, ettersom lyginga til Ravn overraskende nok tok knekken på det automatiske scriptet.

```python
import requests
import math

ENDPOINT = "http://guessing-game"
NUMBERS = 2048
GUESSES = 15
LIES = 1

def ask_question(game_id, question):
    response = requests.post(
        f"{ENDPOINT}/ask_question", json={"game_id": game_id, "question": question}
    )
    return response.json()["answer"]

def start_game():
    response = requests.post(f"{ENDPOINT}/start_game", json={"N": NUMBERS, "M": GUESSES, "K": LIES})
    return response.text

def verify_guess(game_id, guess):
    response = requests.post(
        f"{ENDPOINT}/verify_guess", json={"game_id": game_id, "guess": guess}
    )
    try:
        print(response.json()["flag"])
    except Exception:
        pass
    return response.json()["correct"], response.json()["secret_number"]

def generate_list(lower, upper):
    ls = []
    for i in range(lower, upper+1):
        ls.append(i)
    return ls

def run_example_solver():
    game_id = start_game()

    # Binary search manually
    i = 0
    while i < GUESSES:
        print("-------------------------------")
        print(f"Guesses: {i}")
        user_input = input("lower_range: ")
        if user_input == "m":
            break
        else:
            lower_range = int(user_input)
        upper_range = int(input("upper_range: "))
        mid = math.floor((lower_range + upper_range)/2)
        print(f"Mid: {mid}")
        valid_numbers = generate_list(lower_range, upper_range)
        answer = ask_question(game_id, valid_numbers)
        print(f"Answer = {answer}")
        i += 1

    while i < GUESSES:
        user_input = input("Add numbers: ")
        valid_numbers = []
        while user_input != "m":
            valid_numbers.append(int(user_input))
            user_input = input("Add numbers: ")
        answer = ask_question(game_id, valid_numbers)
        print(f"Answer = {answer}")
        i += 1

    # Make put guess
    guess = int(input("Guess: "))
    correct, secret_number = verify_guess(game_id, guess)
    print(
        f"Guessed {guess} and was {'' if correct else 'in'}correct - answer is {secret_number}"
    )

if __name__ == '__main__':
    run_example_solver()
```
