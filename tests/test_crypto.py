from gatekeeper.crypto import WORDS, generate_phrase, hash_phrase, normalise_phrase, verify_phrase, build_fernet, new_fernet_key


def test_phrase_has_100_bits_of_selection_space():
    assert len(WORDS) == 1024
    assert len(set(WORDS)) == 1024
    phrase = generate_phrase()
    assert len(phrase.split()) == 10
    assert all(word in WORDS for word in phrase.split())


def test_hash_verification_and_whitespace():
    phrase = generate_phrase()
    stored = hash_phrase(phrase)
    assert stored != phrase
    assert verify_phrase(stored, '  ' + phrase.upper().replace(' ', '\n') + '  ')
    wrong = phrase.split()
    wrong[0] = 'unknownword' if wrong[0] != 'unknownword' else 'anotherword'
    assert not verify_phrase(stored, ' '.join(wrong))
    assert not verify_phrase(stored, phrase.split()[0])


def test_escrow_encryption():
    box = build_fernet(new_fernet_key())
    phrase = generate_phrase()
    token = box.encrypt(phrase.encode())
    assert phrase.encode() not in token
    assert box.decrypt(token).decode() == phrase


def test_phrase_normalisation():
    assert normalise_phrase('  A  B\nC  ') == 'a b c'
