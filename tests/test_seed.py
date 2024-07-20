import pytest
from seedsigner.models.seed import InvalidSeedException, Seed, ElectrumSeed

from seedsigner.models.settings import SettingsConstants


# TODO: Change TAB indents to SPACE

def test_seed():
	seed = Seed(mnemonic="obscure bone gas open exotic abuse virus bunker shuffle nasty ship dash".split())
	
	assert seed.seed_bytes == b'q\xb3\xd1i\x0c\x9b\x9b\xdf\xa7\xd9\xd97H\xa8,\xa7\xd9>\xeck\xc2\xf5ND?, \x88-\x07\x9aa\xc5\xee\xb7\xbf\xc4x\xd6\x07 X\xb6}?M\xaa\x05\xa6\xa7(>\xbf\x03\xb0\x9d\xef\xed":\xdf\x88w7'
	
	assert seed.mnemonic_str == "obscure bone gas open exotic abuse virus bunker shuffle nasty ship dash"
	
	assert seed.passphrase == ""
	
	# TODO: Not yet supported in new implementation
	# seed.set_wordlist_language_code("es")
	
	# assert seed.mnemonic_str == "natural ayuda futuro nivel espejo abuelo vago bien repetir moreno relevo conga"
	
	# seed.set_wordlist_language_code(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
	
	# seed.mnemonic_str = "height demise useless trap grow lion found off key clown transfer enroll"
	
	# assert seed.mnemonic_str == "height demise useless trap grow lion found off key clown transfer enroll"
	
	# # TODO: Not yet supported in new implementation
	# seed.set_wordlist_language_code("es")
	
	# assert seed.mnemonic_str == "hebilla cría truco tigre gris llenar folio negocio laico casa tieso eludir"
	
	# seed.set_passphrase("test")
	
	# assert seed.seed_bytes == b'\xdd\r\xcb\x0b V\xb4@\xee+\x01`\xabem\xc1B\xfd\x8fba0\xab;[\xab\xc9\xf9\xba[F\x0c5,\x7fd8\xebI\x90"\xb8\x86C\x821\x01\xdb\xbe\xf3\xbc\x1cBH"%\x18\xc2{\x04\x08a]\xa5'
	
	# assert seed.passphrase == "test"

	
def test_electrum_segwit_seed():
	"""
	ElectrumSeed should correctly parse a Native Segwit Electrum mnemonic.
	"""
	seed = ElectrumSeed(mnemonic="regular reject rare profit once math fringe chase until ketchup century escape".split())

	intended_seed = b'\xcan|\xf8\x8a\x8d\xf78=Pq\xc4_\xe6\x02\x91\xfcs\xb2[\xed*\xdc\xc7%\xb6[_-(~D\xe5\x1e\x85%N\x9c\x03\x9dh\xafX}\x16\xb1\x99,\xbe\xc4\x11\xfaW\x0f\xb0\x89yD\xf4\x0f\xd5?\x8eA'

	assert seed.seed_bytes == intended_seed


def test_electrum_standard_seed():
	"""
	ElectrumSeed should correctly parse a Standard Electrum mnemonic.
	"""
	seed = ElectrumSeed(mnemonic="valve attack fence zero swim frequent visa myth tobacco dismiss useless marble".split())

	intended_seed = b'\x0c$\x97\xb1r\x11{\xdf\xa8\xe6\xb8\xa7!_\xf6\xb9\xacz\x08\xbe5Fa\xeb\xd6\xb7.#\xb6:=\xf7_hZY\xc2\x9b:W\xdc!f\x16\x7f\x98\x99k\x90\x8f1t>Qq\xeb\xf3\x96@\x91}\x19\x1cy'

	assert seed.seed_bytes == intended_seed


def test_electrum_seed_rejects_most_bip39_mnemonics():
	"""
	ElectrumSeed should throw an exception for most BIP-39 mnemonics.

	There are 1/16 odds that a seed will be valid for both formats.
	"""
	# Most BIP-39 seeds should fail; test seeds generated by bitcoiner.guide
	with pytest.raises(InvalidSeedException):
		ElectrumSeed(mnemonic="pioneer divide volcano art victory family grow novel mandate bicycle senior adjust".split())

	with pytest.raises(InvalidSeedException):
		ElectrumSeed(mnemonic="gentle combine cool hamster ghost harvest gossip lend dismiss slam any toast".split())

	with pytest.raises(InvalidSeedException):
		ElectrumSeed(mnemonic="enough board blossom stamp fire buffalo digital solution sadness random number stone".split())

	# This one is valid for both formats
	mnemonic = "only gain spot output unknown craft simple cram absorb suggest ridge famous".split()
	Seed(mnemonic)
	ElectrumSeed(mnemonic)
