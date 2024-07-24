from dataclasses import dataclass
import hashlib
import logging
import os
import time
import json
import string
import math

from embit.descriptor import Descriptor
from PIL import Image
from PIL.ImageOps import autocontrast

from seedsigner.controller import Controller
from seedsigner.gui.components import FontAwesomeIconConstants, GUIConstants, SeedSignerIconConstants
from seedsigner.gui.screens import (RET_CODE__BACK_BUTTON, ButtonListScreen, WarningScreen)
from seedsigner.gui.screens.tools_screens import (ToolsCalcFinalWordDoneScreen, ToolsCalcFinalWordFinalizePromptScreen,
    ToolsCalcFinalWordScreen, ToolsCoinFlipEntryScreen, ToolsDiceEntropyEntryScreen, ToolsImageEntropyFinalImageScreen,
    ToolsImageEntropyLivePreviewScreen, ToolsAddressExplorerAddressTypeScreen)
from seedsigner.helpers import embit_utils, mnemonic_generation
from seedsigner.models.encode_qr import GenericStaticQrEncoder
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.seed_views import SeedDiscardView, SeedFinalizeView, SeedMnemonicEntryView, SeedOptionsView, SeedWordsWarningView, SeedExportXpubScriptTypeView

from .view import View, Destination, BackStackView

logger = logging.getLogger(__name__)


class ToolsMenuView(View):
    IMAGE = (" New seed", FontAwesomeIconConstants.CAMERA)
    DICE = ("New seed", FontAwesomeIconConstants.DICE)
    KEYBOARD = ("Calc 12th/24th word", FontAwesomeIconConstants.KEYBOARD)
    ADDRESS_EXPLORER = "Address Explorer"
    VERIFY_ADDRESS = "Verify address"
    PWMGR = "Password Manager"

    def run(self):
        button_data = [self.IMAGE, self.DICE, self.KEYBOARD, self.ADDRESS_EXPLORER, self.VERIFY_ADDRESS, self.PWMGR]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Tools",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.IMAGE:
            return Destination(ToolsImageEntropyLivePreviewView)

        elif button_data[selected_menu_num] == self.DICE:
            return Destination(ToolsDiceEntropyMnemonicLengthView)

        elif button_data[selected_menu_num] == self.KEYBOARD:
            return Destination(ToolsCalcFinalWordNumWordsView)

        elif button_data[selected_menu_num] == self.ADDRESS_EXPLORER:
            return Destination(ToolsAddressExplorerSelectSourceView)

        elif button_data[selected_menu_num] == self.VERIFY_ADDRESS:
            from seedsigner.views.scan_views import ScanAddressView
            return Destination(ScanAddressView)

        #TODO: Put under advanced option
        elif button_data[selected_menu_num] == self.PWMGR:
            return Destination(PwmgrStartView)



"""****************************************************************************
    Image entropy Views
****************************************************************************"""
class ToolsImageEntropyLivePreviewView(View):
    def run(self):
        self.controller.image_entropy_preview_frames = None
        ret = ToolsImageEntropyLivePreviewScreen().display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        self.controller.image_entropy_preview_frames = ret
        return Destination(ToolsImageEntropyFinalImageView)



class ToolsImageEntropyFinalImageView(View):
    def run(self):
        if not self.controller.image_entropy_final_image:
            from seedsigner.hardware.camera import Camera
            # Take the final full-res image
            camera = Camera.get_instance()
            camera.start_single_frame_mode(resolution=(720, 480))
            time.sleep(0.25)
            self.controller.image_entropy_final_image = camera.capture_frame()
            camera.stop_single_frame_mode()

        # Prep a copy of the image for display. The actual image data is 720x480
        # Present just a center crop and resize it to fit the screen and to keep some of
        #   the data hidden.
        display_version = autocontrast(
            self.controller.image_entropy_final_image,
            cutoff=2
        ).crop(
            (120, 0, 600, 480)
        ).resize(
            (self.canvas_width, self.canvas_height), Image.BICUBIC
        )
        
        ret = ToolsImageEntropyFinalImageScreen(
            final_image=display_version
        ).display()

        if ret == RET_CODE__BACK_BUTTON:
            # Go back to live preview and reshoot
            self.controller.image_entropy_final_image = None
            return Destination(BackStackView)
        
        if self.controller.resume_main_flow == Controller.FLOW__GENERATE_PASS:
            return Destination(PwmgrGeneratePassLengthView, skip_current_view = True)

        return Destination(ToolsImageEntropyMnemonicLengthView)



class ToolsImageEntropyMnemonicLengthView(View):
    def run(self):
        TWELVE_WORDS = "12 words"
        TWENTYFOUR_WORDS = "24 words"
        button_data = [TWELVE_WORDS, TWENTYFOUR_WORDS]

        selected_menu_num = ButtonListScreen(
            title="Mnemonic Length?",
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        if button_data[selected_menu_num] == TWELVE_WORDS:
            mnemonic_length = 12
        else:
            mnemonic_length = 24

        preview_images = self.controller.image_entropy_preview_frames
        seed_entropy_image = self.controller.image_entropy_final_image

        # Build in some hardware-level uniqueness via CPU unique Serial num
        try:
            stream = os.popen("cat /proc/cpuinfo | grep Serial")
            output = stream.read()
            serial_num = output.split(":")[-1].strip().encode('utf-8')
            serial_hash = hashlib.sha256(serial_num)
            hash_bytes = serial_hash.digest()
        except Exception as e:
            logger.info(repr(e), exc_info=True)
            hash_bytes = b'0'

        # Build in modest entropy via millis since power on
        millis_hash = hashlib.sha256(hash_bytes + str(time.time()).encode('utf-8'))
        hash_bytes = millis_hash.digest()

        # Build in better entropy by chaining the preview frames
        for frame in preview_images:
            img_hash = hashlib.sha256(hash_bytes + frame.tobytes())
            hash_bytes = img_hash.digest()

        # Finally build in our headline entropy via the new full-res image
        final_hash = hashlib.sha256(hash_bytes + seed_entropy_image.tobytes()).digest()

        if mnemonic_length == 12:
            # 12-word mnemonic only uses the first 128 bits / 16 bytes of entropy
            final_hash = final_hash[:16]

        # Generate the mnemonic
        mnemonic = mnemonic_generation.generate_mnemonic_from_bytes(final_hash)

        # Image should never get saved nor stick around in memory
        seed_entropy_image = None
        preview_images = None
        final_hash = None
        hash_bytes = None
        self.controller.image_entropy_preview_frames = None
        self.controller.image_entropy_final_image = None

        # Add the mnemonic as an in-memory Seed
        seed = Seed(mnemonic, wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
        self.controller.storage.set_pending_seed(seed)
        
        # Cannot return BACK to this View
        return Destination(SeedWordsWarningView, view_args={"seed_num": None}, clear_history=True)



"""****************************************************************************
    Dice rolls Views
****************************************************************************"""
class ToolsDiceEntropyMnemonicLengthView(View):
    def run(self):
        TWELVE = f"12 words ({mnemonic_generation.DICE__NUM_ROLLS__12WORD} rolls)"
        TWENTY_FOUR = f"24 words ({mnemonic_generation.DICE__NUM_ROLLS__24WORD} rolls)"
        
        button_data = [TWELVE, TWENTY_FOUR]
        selected_menu_num = ButtonListScreen(
            title="Mnemonic Length",
            is_bottom_list=True,
            is_button_text_centered=True,
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == TWELVE:
            return Destination(ToolsDiceEntropyEntryView, view_args=dict(total_rolls=mnemonic_generation.DICE__NUM_ROLLS__12WORD))

        elif button_data[selected_menu_num] == TWENTY_FOUR:
            return Destination(ToolsDiceEntropyEntryView, view_args=dict(total_rolls=mnemonic_generation.DICE__NUM_ROLLS__24WORD))



class ToolsDiceEntropyEntryView(View):
    def __init__(self, total_rolls: int):
        super().__init__()
        self.total_rolls = total_rolls
    

    def run(self):
        ret = ToolsDiceEntropyEntryScreen(
            return_after_n_chars=self.total_rolls,
        ).display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        dice_seed_phrase = mnemonic_generation.generate_mnemonic_from_dice(ret)

        # Add the mnemonic as an in-memory Seed
        seed = Seed(dice_seed_phrase, wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
        self.controller.storage.set_pending_seed(seed)

        # Cannot return BACK to this View
        return Destination(SeedWordsWarningView, view_args={"seed_num": None}, clear_history=True)



"""****************************************************************************
    Calc final word Views
****************************************************************************"""
class ToolsCalcFinalWordNumWordsView(View):
    TWELVE = "12 words"
    TWENTY_FOUR = "24 words"

    def run(self):
        button_data = [self.TWELVE, self.TWENTY_FOUR]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Mnemonic Length",
            is_bottom_list=True,
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.TWELVE:
            self.controller.storage.init_pending_mnemonic(12)

            # return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True))
            return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True))

        elif button_data[selected_menu_num] == self.TWENTY_FOUR:
            self.controller.storage.init_pending_mnemonic(24)

            # return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True))
            return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True))



class ToolsCalcFinalWordFinalizePromptView(View):
    def run(self):
        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_length = len(mnemonic)
        if mnemonic_length == 12:
            num_entropy_bits = 7
        else:
            num_entropy_bits = 3

        COIN_FLIPS = "Coin flip entropy"
        SELECT_WORD = f"Word selection entropy"
        ZEROS = "Finalize with zeros"

        button_data = [COIN_FLIPS, SELECT_WORD, ZEROS]
        selected_menu_num = ToolsCalcFinalWordFinalizePromptScreen(
            mnemonic_length=mnemonic_length,
            num_entropy_bits=num_entropy_bits,
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == COIN_FLIPS:
            return Destination(ToolsCalcFinalWordCoinFlipsView)

        elif button_data[selected_menu_num] == SELECT_WORD:
            # Clear the final word slot, just in case we're returning via BACK button
            self.controller.storage.update_pending_mnemonic(None, mnemonic_length - 1)
            return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True, cur_word_index=mnemonic_length - 1))

        elif button_data[selected_menu_num] == ZEROS:
            # User skipped the option to select a final word to provide last bits of
            # entropy. We'll insert all zeros and piggy-back on the coin flip attr
            wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
            self.controller.storage.update_pending_mnemonic(Seed.get_wordlist(wordlist_language_code)[0], mnemonic_length - 1)
            return Destination(ToolsCalcFinalWordShowFinalWordView, view_args=dict(coin_flips="0" * num_entropy_bits))



class ToolsCalcFinalWordCoinFlipsView(View):
    def run(self):
        mnemonic_length = len(self.controller.storage.pending_mnemonic)

        if mnemonic_length == 12:
            total_flips = 7
        else:
            total_flips = 3
        
        ret_val = ToolsCoinFlipEntryScreen(
            return_after_n_chars=total_flips,
        ).display()

        if ret_val == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        else:
            return Destination(ToolsCalcFinalWordShowFinalWordView, view_args=dict(coin_flips=ret_val))



class ToolsCalcFinalWordShowFinalWordView(View):
    def __init__(self, coin_flips: str = None):
        super().__init__()
        # Construct the actual final word. The user's selected_final_word
        # contributes:
        #   * 3 bits to a 24-word seed (plus 8-bit checksum)
        #   * 7 bits to a 12-word seed (plus 4-bit checksum)
        from seedsigner.helpers import mnemonic_generation

        wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        wordlist = Seed.get_wordlist(wordlist_language_code)

        # Prep the user's selected word / coin flips and the actual final word for
        # the display.
        if coin_flips:
            self.selected_final_word = None
            self.selected_final_bits = coin_flips
        else:
            # Convert the user's final word selection into its binary index equivalent
            self.selected_final_word = self.controller.storage.pending_mnemonic[-1]
            self.selected_final_bits = format(wordlist.index(self.selected_final_word), '011b')

        if coin_flips:
            # fill the last bits (what will eventually be the checksum) with zeros
            binary_string = coin_flips + "0" * (11 - len(coin_flips))

            # retrieve the matching word for the resulting index
            wordlist_index = int(binary_string, 2)
            wordlist = Seed.get_wordlist(self.controller.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
            word = wordlist[wordlist_index]

            # update the pending mnemonic with our new "final" (pre-checksum) word
            self.controller.storage.update_pending_mnemonic(word, -1)

        # Now calculate the REAL final word (has a proper checksum)
        final_mnemonic = mnemonic_generation.calculate_checksum(
            mnemonic=self.controller.storage.pending_mnemonic,
            wordlist_language_code=wordlist_language_code,
        )

        # Update our pending mnemonic with the real final word
        self.controller.storage.update_pending_mnemonic(final_mnemonic[-1], -1)

        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_length = len(mnemonic)

        # And grab the actual final word's checksum bits
        self.actual_final_word = self.controller.storage.pending_mnemonic[-1]
        num_checksum_bits = 4 if mnemonic_length == 12 else 8
        self.checksum_bits = format(wordlist.index(self.actual_final_word), '011b')[-num_checksum_bits:]


    def run(self):
        NEXT = "Next"
        button_data = [NEXT]
        selected_menu_num = self.run_screen(
            ToolsCalcFinalWordScreen,
            title="Final Word Calc",
            button_data=button_data,
            selected_final_word=self.selected_final_word,
            selected_final_bits=self.selected_final_bits,
            checksum_bits=self.checksum_bits,
            actual_final_word=self.actual_final_word,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == NEXT:
            return Destination(ToolsCalcFinalWordDoneView)



class ToolsCalcFinalWordDoneView(View):
    def run(self):
        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_word_length = len(mnemonic)
        final_word = mnemonic[-1]

        LOAD = "Load seed"
        DISCARD = ("Discard", None, None, "red")
        button_data = [LOAD, DISCARD]

        selected_menu_num = ToolsCalcFinalWordDoneScreen(
            final_word=final_word,
            mnemonic_word_length=mnemonic_word_length,
            fingerprint=self.controller.storage.get_pending_mnemonic_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK)),
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        self.controller.storage.convert_pending_mnemonic_to_pending_seed()

        if button_data[selected_menu_num] == LOAD:
            return Destination(SeedFinalizeView)
        
        elif button_data[selected_menu_num] == DISCARD:
            return Destination(SeedDiscardView)


"""****************************************************************************
    Address Explorer Views
****************************************************************************"""
class ToolsAddressExplorerSelectSourceView(View):
    SCAN_SEED = ("Scan a seed", SeedSignerIconConstants.QRCODE)
    SCAN_DESCRIPTOR = ("Scan wallet descriptor", SeedSignerIconConstants.QRCODE)
    TYPE_12WORD = ("Enter 12-word seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_24WORD = ("Enter 24-word seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_ELECTRUM = ("Enter Electrum seed", FontAwesomeIconConstants.KEYBOARD)


    def run(self):
        seeds = self.controller.storage.seeds
        button_data = []
        for seed in seeds:
            button_str = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            button_data.append((button_str, SeedSignerIconConstants.FINGERPRINT))
        button_data = button_data + [self.SCAN_SEED, self.SCAN_DESCRIPTOR, self.TYPE_12WORD, self.TYPE_24WORD]
        if self.settings.get_value(SettingsConstants.SETTING__ELECTRUM_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_ELECTRUM)
        
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Address Explorer",
            button_data=button_data,
            is_button_text_centered=False,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Most of the options require us to go through a side flow(s) before we can
        # continue to the address explorer. Set the Controller-level flow so that it
        # knows to re-route us once the side flow is complete.        
        self.controller.resume_main_flow = Controller.FLOW__ADDRESS_EXPLORER

        if len(seeds) > 0 and selected_menu_num < len(seeds):
            # User selected one of the n seeds
            return Destination(
                SeedExportXpubScriptTypeView,
                view_args=dict(
                    seed_num=selected_menu_num,
                    sig_type=SettingsConstants.SINGLE_SIG,
                )
            )

        elif button_data[selected_menu_num] == self.SCAN_SEED:
            from seedsigner.views.scan_views import ScanSeedQRView
            return Destination(ScanSeedQRView)

        elif button_data[selected_menu_num] == self.SCAN_DESCRIPTOR:
            from seedsigner.views.scan_views import ScanWalletDescriptorView
            return Destination(ScanWalletDescriptorView)

        elif button_data[selected_menu_num] in [self.TYPE_12WORD, self.TYPE_24WORD]:
            from seedsigner.views.seed_views import SeedMnemonicEntryView
            if button_data[selected_menu_num] == self.TYPE_12WORD:
                self.controller.storage.init_pending_mnemonic(num_words=12)
            else:
                self.controller.storage.init_pending_mnemonic(num_words=24)
            return Destination(SeedMnemonicEntryView)

        elif button_data[selected_menu_num] == self.TYPE_ELECTRUM:
            from seedsigner.views.seed_views import SeedElectrumMnemonicStartView
            return Destination(SeedElectrumMnemonicStartView)



class ToolsAddressExplorerAddressTypeView(View):
    RECEIVE = "Receive Addresses"
    CHANGE = "Change Addresses"


    def __init__(self, seed_num: int = None, script_type: str = None, custom_derivation: str = None):
        """
            If the explorer source is a seed, `seed_num` and `script_type` must be
            specified. `custom_derivation` can be specified as needed.

            If the source is a multisig or single sig wallet descriptor, `seed_num`,
            `script_type`, and `custom_derivation` should be `None`.
        """
        super().__init__()
        self.seed_num = seed_num
        self.script_type = script_type
        self.custom_derivation = custom_derivation
    
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)

        # Store everything in the Controller's `address_explorer_data` so we don't have
        # to keep passing vals around from View to View and recalculating.
        data = dict(
            seed_num=seed_num,
            network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
            embit_network=SettingsConstants.map_network_to_embit(network),
            script_type=script_type,
        )
        if self.seed_num is not None:
            self.seed = self.controller.storage.seeds[seed_num]
            data["seed_num"] = self.seed
            seed_derivation_override = self.seed.derivation_override(sig_type=SettingsConstants.SINGLE_SIG)

            if self.script_type == SettingsConstants.CUSTOM_DERIVATION:
                derivation_path = self.custom_derivation
            elif seed_derivation_override:
                derivation_path = seed_derivation_override
            else:
                derivation_path = embit_utils.get_standard_derivation_path(
                    network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
                    wallet_type=SettingsConstants.SINGLE_SIG,
                    script_type=self.script_type,
                )

            data["derivation_path"] = derivation_path
            data["xpub"] = self.seed.get_xpub(derivation_path, network=network)
        
        else:
            data["wallet_descriptor"] = self.controller.multisig_wallet_descriptor

        self.controller.address_explorer_data = data


    def run(self):
        data = self.controller.address_explorer_data

        wallet_descriptor_display_name = None
        if "wallet_descriptor" in data:
            wallet_descriptor_display_name = data["wallet_descriptor"].brief_policy.replace(" (sorted)", "")

        script_type = data["script_type"] if "script_type" in data else None

        button_data = [self.RECEIVE, self.CHANGE]

        selected_menu_num = self.run_screen(
            ToolsAddressExplorerAddressTypeScreen,
            button_data=button_data,
            fingerprint=self.seed.get_fingerprint() if self.seed_num is not None else None,
            wallet_descriptor_display_name=wallet_descriptor_display_name,
            script_type=script_type,
            custom_derivation_path=self.custom_derivation,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            # If we entered this flow via an already-loaded seed's SeedOptionsView, we
            # need to clear the `resume_main_flow` so that we don't get stuck in a 
            # SeedOptionsView redirect loop.
            # TODO: Refactor to a cleaner `BackStack.get_previous_View_cls()`
            if len(self.controller.back_stack) > 1 and self.controller.back_stack[-2].View_cls == SeedOptionsView:
                # The BackStack has the current View on the top with the real "back" in second position.
                self.controller.resume_main_flow = None
                self.controller.address_explorer_data = None
            return Destination(BackStackView)
        
        elif button_data[selected_menu_num] in [self.RECEIVE, self.CHANGE]:
            return Destination(ToolsAddressExplorerAddressListView, view_args=dict(is_change=button_data[selected_menu_num] == self.CHANGE))



class ToolsAddressExplorerAddressListView(View):
    def __init__(self, is_change: bool = False, start_index: int = 0, selected_button_index: int = 0, initial_scroll: int = 0):
        super().__init__()
        self.is_change = is_change
        self.start_index = start_index
        self.selected_button_index = selected_button_index
        self.initial_scroll = initial_scroll


    def run(self):
        self.loading_screen = None

        addresses = []
        button_data = []
        data = self.controller.address_explorer_data
        addrs_per_screen = 10

        addr_storage_key = "receive_addrs"
        if self.is_change:
            addr_storage_key = "change_addrs"

        if addr_storage_key in data and len(data[addr_storage_key]) >= self.start_index + addrs_per_screen:
            # We already calculated this range of addresses; just retrieve them
            addresses = data[addr_storage_key][self.start_index:self.start_index + addrs_per_screen]

        else:
            try:
                from seedsigner.gui.screens.screen import LoadingScreenThread
                self.loading_screen = LoadingScreenThread(text="Calculating addrs...")
                self.loading_screen.start()

                if addr_storage_key not in data:
                    data[addr_storage_key] = []

                if "xpub" in data:
                    # Single sig explore from seed
                    if "script_type" in data and data["script_type"] != SettingsConstants.CUSTOM_DERIVATION:
                        # Standard derivation path
                        for i in range(self.start_index, self.start_index + addrs_per_screen):
                            address = embit_utils.get_single_sig_address(xpub=data["xpub"], script_type=data["script_type"], index=i, is_change=self.is_change, embit_network=data["embit_network"])
                            addresses.append(address)
                            data[addr_storage_key].append(address)
                    else:
                        # TODO: Custom derivation path
                        raise Exception("Custom Derivation address explorer not yet implemented")
                
                elif "wallet_descriptor" in data:
                    descriptor: Descriptor = data["wallet_descriptor"]
                    if descriptor.is_basic_multisig:
                        for i in range(self.start_index, self.start_index + addrs_per_screen):
                            address = embit_utils.get_multisig_address(descriptor=descriptor, index=i, is_change=self.is_change, embit_network=data["embit_network"])
                            addresses.append(address)
                            data[addr_storage_key].append(address)

                    else:
                        raise Exception("Single sig descriptors not yet supported")
            finally:
                # Everything is set. Stop the loading screen
                self.loading_screen.stop()

        for i, address in enumerate(addresses):
            cur_index = i + self.start_index

            # Adjust the trailing addr display length based on available room
            # (the index number will push it out on each order of magnitude)
            if cur_index < 10:
                end_digits = -6
            elif cur_index < 100:
                end_digits = -5
            else:
                end_digits = -4
            button_data.append(f"{cur_index}:{address[:8]}...{address[end_digits:]}")

        button_data.append(("Next {}".format(addrs_per_screen), None, None, None, SeedSignerIconConstants.CHEVRON_RIGHT))

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="{} Addrs".format("Receive" if not self.is_change else "Change"),
            button_data=button_data,
            button_font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            button_font_size=GUIConstants.BUTTON_FONT_SIZE + 4,
            is_button_text_centered=False,
            is_bottom_list=True,
            selected_button=self.selected_button_index,
            scroll_y_initial_offset=self.initial_scroll,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        if selected_menu_num == len(addresses):
            # User clicked NEXT
            return Destination(ToolsAddressExplorerAddressListView, view_args=dict(is_change=self.is_change, start_index=self.start_index + addrs_per_screen))
        
        # Preserve the list's current scroll so we can return to the same spot
        initial_scroll = self.screen.buttons[0].scroll_y

        index = selected_menu_num + self.start_index
        return Destination(ToolsAddressExplorerAddressView, view_args=dict(index=index, address=addresses[selected_menu_num], is_change=self.is_change, start_index=self.start_index, parent_initial_scroll=initial_scroll), skip_current_view=True)



class ToolsAddressExplorerAddressView(View):
    def __init__(self, index: int, address: str, is_change: bool, start_index: int, parent_initial_scroll: int = 0):
        super().__init__()
        self.index = index
        self.address = address
        self.is_change = is_change
        self.start_index = start_index
        self.parent_initial_scroll = parent_initial_scroll

    
    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        qr_encoder = GenericStaticQrEncoder(data=self.address)
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )
    
        # Exiting/Cancelling the QR display screen always returns to the list
        return Destination(ToolsAddressExplorerAddressListView, view_args=dict(is_change=self.is_change, start_index=self.start_index, selected_button_index=self.index - self.start_index, initial_scroll=self.parent_initial_scroll), skip_current_view=True)



class PwmgrStartView(View):
    SCAN_PWMGR = ("Scan existing", SeedSignerIconConstants.QRCODE)
    NEW_PWMGR = ("New PWMgr", FontAwesomeIconConstants.SQUARE_PLUS)

    def run(self):
        
        button_data = [
            self.SCAN_PWMGR,
            self.NEW_PWMGR,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="PWMgr",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            self.controller.pwmgr_data = None
            return Destination(BackStackView)
        
        if button_data[selected_menu_num] == self.SCAN_PWMGR:
            from seedsigner.views.scan_views import ScanView
            return Destination(ScanView)

        elif button_data[selected_menu_num] == self.NEW_PWMGR:
            if not self.controller.pwmgr_data:
                self.controller.pwmgr_data = dict(pwmgr_dict={})
            self.controller.pwmgr_data['pwmgr_dict'] = {}
            return Destination(PwmgrManageView)


class PwmgrStartDecryptView(View):
    """
    Routes users straight through to the "Decrypt" view if a pwmgr `seed_num` has
    already been selected. Otherwise routes to `SeedSelectSeedView` to select or
    load a seed first.
    """
    def __init__(self, encrypted_pwmgr: str = None):
        super().__init__()
        self.encrypted_pwmgr = encrypted_pwmgr

        #if self.settings.get_value(SettingsConstants.SETTING__MESSAGE_SIGNING) == SettingsConstants.OPTION__DISABLED:
            #self.set_redirect(Destination(OptionDisabledView, view_args=dict(settings_attr=SettingsConstants.SETTING__MESSAGE_SIGNING)))
            #return

        data = self.controller.pwmgr_data
        if not data:
            data = {}
            self.controller.pwmgr_data = data
        
        if encrypted_pwmgr is not None:
            self.controller.pwmgr_data["encrypted_pwmgr"] = encrypted_pwmgr
        # May be None
        self.seed_num = data.get("seed_num")
    
        if self.seed_num is not None:
            # We already know which seed we're signing with
            self.set_redirect(Destination(PwmgrDecryptView, skip_current_view=True))
        else:
            from seedsigner.views.seed_views import SeedSelectSeedView
            self.set_redirect(Destination(SeedSelectSeedView, view_args=dict(flow=Controller.FLOW__DECRYPT_PWMGR), skip_current_view=True))



class PwmgrDecryptView(View):
    """
    """
    def __init__(self):
        super().__init__()

    def run(self):
        seed = self.controller.get_seed(self.controller.pwmgr_data['seed_num'])
        encrypted_pwmgr = self.controller.pwmgr_data['encrypted_pwmgr']
        xprv = seed.get_xprv(wallet_path='m/0h', network=self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        childkey = xprv.derive([0,0])
        from seedsigner.helpers.ecies import ecies_decrypt_message

        try:
            decrypted = ecies_decrypt_message(childkey.key, encrypted_pwmgr)
        except Exception as e:
            exceptionMessage = str(e)
            if "InvalidPassword" == exceptionMessage:
                DireWarningScreen(
                    title="Incorrect Seed",
                    status_headline="Error!",
                    text="Your decryption seed does not match the encryption seed!",
                    show_back_button=False
               ).display()
            else:
                DireWarningScreen(
                    title="Error Decrypting",
                    status_headline="Error!",
                    text=exceptionMessage,
                    show_back_button=False
               ).display()

            from seedsigner.views.view import MainMenuView
            self.controller.resume_main_flow = None
            return Destination(MainMenuView)

        try:
            self.controller.pwmgr_data['pwmgr_dict'] = json.loads(decrypted.decode())
        except Exception as e:
            DireWarningScreen(
                title="Not valid PWMgr data",
                status_headline="Error!",
                text=str(e),
                show_back_button=False
            ).display()
            from seedsigner.views.view import MainMenuView
            self.controller.resume_main_flow = None
            return Destination(MainMenuView)

        self.controller.sign_message_data = dict()
        self.controller.sign_message_data["message"] = decrypted.decode()
        return Destination(PwmgrManageView)



class PwmgrManageView(View):
    ENTRIES = "Entries"
    EXPORT = ("Export Encrypted", SeedSignerIconConstants.QRCODE)

    def run(self):
        
        if not 'entries' in self.controller.pwmgr_data['pwmgr_dict']:
            self.controller.pwmgr_data['pwmgr_dict']['entries'] = list()
            return Destination(PwmgrManageEntriesView)

        entries = self.controller.pwmgr_data['pwmgr_dict']['entries']
        button_data = [
            self.ENTRIES,
        ]
        if len(entries)>0:
            button_data.append(self.EXPORT)

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="PWMgr",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            if len(entries) > 0:
                return Destination(PwmgrExitConfirmView)
            else:
                return Destination(BackStackView)
        
        elif button_data[selected_menu_num] == self.ENTRIES:
            return Destination(PwmgrManageEntriesView)

        elif button_data[selected_menu_num] == self.EXPORT:
            # allow user to select seed to encrypt.  May differ from one used to decrypt.
            from seedsigner.views.seed_views import SeedSelectSeedView
            return Destination(SeedSelectSeedView, view_args=dict(flow=Controller.FLOW__ENCRYPT_PWMGR))
        



class PwmgrExitConfirmView(View):
    EDIT = "Review & Edit"
    DISCARD = ("Exit & Discard", None, None, "red")

    def run(self):
        button_data = [self.EDIT, self.DISCARD]
        selected_menu_num = self.run_screen(
            WarningScreen,
            title="Exiting PWMgr!",
            status_headline=None,
            text="PWMgr will be discarded, have you exported the encrypted data yet?",
            show_back_button=False,
            button_data=button_data,
        )
        if button_data[selected_menu_num] == self.EDIT:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.DISCARD:
            self.controller.pwmgr_data = None
            self.controller.resume_main_flow = None
            from seedsigner.views.view import MainMenuView
            return Destination(MainMenuView, clear_history=True)
        



class PwmgrExportView(View):
    def __init__(self):
        super().__init__()


    def run(self):
        from seedsigner.helpers.ecies import ecies_encrypt_message

        seed = self.controller.get_seed(self.controller.pwmgr_data['seed_num'])
        xprv = seed.get_xprv(wallet_path='m/0h', network=self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        childkey = xprv.derive([0,0])

        s = json.dumps(self.controller.pwmgr_data["pwmgr_dict"])

        encrypted = ecies_encrypt_message(childkey.get_public_key(), s.encode())

        encoder_args = dict(
            encrypted_data=encrypted.decode(),
            qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
        )

        from seedsigner.models.encode_qr import PwmgrQrEncoder
        self.qr_encoder = PwmgrQrEncoder(**encoder_args)

        from seedsigner.gui.screens.screen import QRDisplayScreen
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=self.qr_encoder
        )

        return Destination(BackStackView)



class PwmgrManageEntriesView(View):
    NEW_ENTRY = ("New Entry", FontAwesomeIconConstants.SQUARE_PLUS)
    def __init__(self):
        super().__init__()


    def run(self):
        
        button_data = [
            self.NEW_ENTRY
        ]
        entries = self.controller.pwmgr_data['pwmgr_dict']['entries']
        for entry in entries:
            button_text = entry['Title'] if 'Title' in entry else ''
            button_data.append(button_text)

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="PWMgr Entries",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            #return Destination(PwmgrManageView)
            return Destination(BackStackView)
        
        elif button_data[selected_menu_num] == self.NEW_ENTRY:
            entry = dict()
            entries.append(entry)
            self.controller.pwmgr_data['selected_index'] = len(entries)-1
            return Destination(PwmgrManageEntryView)

        else:
            entry_index = selected_menu_num-1
            self.controller.pwmgr_data['selected_index'] = entry_index
            return Destination(PwmgrManageEntryView)



class PwmgrManageEntryView(View): 
    VIEW = "View"
    EDIT = "Edit"
    DELETE = ("Delete Entry", None, None, "red")

    def run(self):
        entry_index = self.controller.pwmgr_data['selected_index']
        entry = self.controller.pwmgr_data["pwmgr_dict"]['entries'][entry_index]

        title = entry["Title"] if "Title" in entry else "PWMgr Entry"
        
        button_data = [
            self.VIEW,
            self.EDIT,
            self.DELETE,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=title,
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            if 0==len(entry):
                # cleared all fields in edit.  Remove empty entry
                del self.controller.pwmgr_data['pwmgr_dict']['entries'][entry_index]
            del self.controller.pwmgr_data['selected_index']
            #return Destination(PwmgrManageEntriesView)
            return Destination(BackStackView)
        
        elif button_data[selected_menu_num] == self.VIEW:
            title = "Entry"
            s : str = ""
            for key in entry:
                if 'Title' == key:
                    title = entry[key]
                    continue
                if s: #newline between keys but not before first
                    s+="\n"
                
                s+= key + ":\n" + entry[key]
            self.controller.pwmgr_data['formatted_entry'] = s
            return Destination(PwmgrViewEntryView, view_args=dict(title=title))

        elif button_data[selected_menu_num] == self.EDIT:
            return Destination(PwmgrEditEntryView)

        elif button_data[selected_menu_num] == self.DELETE:
            #TODO: ask for confirmation
            del self.controller.pwmgr_data['pwmgr_dict']['entries'][entry_index]
            del self.controller.pwmgr_data['selected_index']
            #return Destination(PwmgrManageEntriesView)
            return Destination(BackStackView)
 


class PwmgrEditEntryView(View): 
    ADD_FIELD = ("New Field", FontAwesomeIconConstants.SQUARE_PLUS)

    def run(self):
        entry_index = self.controller.pwmgr_data['selected_index']
        entry = self.controller.pwmgr_data["pwmgr_dict"]['entries'][entry_index]
        title = entry["Title"] if "Title" in entry else "PWMgr Entry"
        
        button_data = [
                'Title',
                'Site',
                'User',
                'Pass',
                'Note',
                ]
        for key in entry:
            if key not in button_data:
                button_data.append(key)

        button_data.append(self.ADD_FIELD)

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=title,
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            #return Destination(PwmgrManageEntryView)
            return Destination(BackStackView)
        
        elif button_data[selected_menu_num] == self.ADD_FIELD:
            return Destination(PwmgrAddFieldView)

        elif button_data[selected_menu_num] == 'Pass':
            return Destination(PwmgrEditPassView)
        else: #field key selected
            return Destination(PwmgrEditFieldView, view_args=dict(field_name=button_data[selected_menu_num]))
            


class PwmgrEditPassView(View): 
    GENERATE_CAM = ("Generate New", FontAwesomeIconConstants.CAMERA)
    MANUAL_EDIT = ("Manual Edit", FontAwesomeIconConstants.KEYBOARD)

    def run(self):
        entry_index = self.controller.pwmgr_data['selected_index']
        button_data = [
                self.GENERATE_CAM,
                self.MANUAL_EDIT,
                ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title='Change Pass',
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            #return Destination(PwmgrManageEntryView)
            return Destination(BackStackView)
        
        elif button_data[selected_menu_num] == self.GENERATE_CAM:
            self.controller.resume_main_flow = self.controller.FLOW__GENERATE_PASS
            return Destination(ToolsImageEntropyLivePreviewView, skip_current_view=True)
            #return Destination(PwmgrEditFieldView, view_args=dict(field_name='Pass'), skip_current_view=True)

        elif button_data[selected_menu_num] == self.MANUAL_EDIT:
            return Destination(PwmgrEditFieldView, view_args=dict(field_name='Pass'), skip_current_view=True)
            



class PwmgrAddFieldView(View):

    def run(self):
        entry_index = self.controller.pwmgr_data['selected_index']
        entry = self.controller.pwmgr_data["pwmgr_dict"]['entries'][entry_index]


        from seedsigner.gui.screens.seed_screens import SeedAddPassphraseScreen
        ret_dict = self.run_screen(SeedAddPassphraseScreen, passphrase="", title="Field name")

        # The new passphrase will be the return value; it might be empty.
        new_field_name = ret_dict["passphrase"]

        if "is_back_button" in ret_dict:
            return Destination(BackStackView)
            
        elif len(new_field_name) > 0:
            entry[new_field_name]=""
            return Destination(PwmgrEditFieldView, view_args=dict(field_name=new_field_name), skip_current_view=True)

        else:
            #empty, go back as if we didn't enter here
            return Destination(BackStackView)



 
class PwmgrEditFieldView(View):

    def __init__(self, field_name : str = ""):
            super().__init__()
            self.field_name = field_name

    def run(self):
        entry_index = self.controller.pwmgr_data['selected_index']
        entry = self.controller.pwmgr_data["pwmgr_dict"]['entries'][entry_index]
        old_value = entry[self.field_name] if self.field_name in entry else ""

        from seedsigner.gui.screens.seed_screens import SeedAddPassphraseScreen
        title = "Edit " + self.field_name
        ret_dict = self.run_screen(SeedAddPassphraseScreen, passphrase=old_value, title=title)

        # The new passphrase will be the return value; it might be empty.
        new_value = ret_dict["passphrase"]


        if "is_back_button" in ret_dict:
            # in case we were adding new field
            if self.field_name in entry and 0==len(entry[self.field_name]):
                del entry[self.field_name]
            
        elif len(new_value) > 0:
            entry[self.field_name] = new_value

        elif self.field_name in entry:
            del entry[self.field_name]

        return Destination(BackStackView)


 
class PwmgrViewEntryView(View):
    def __init__(self, page_num: int = 0, title: str = "Entry"):
        super().__init__()
        self.page_num = page_num  # Note: zero-indexed numbering!
        self.title = title


    def run(self):
        from seedsigner.gui.screens.tools_screens import PwmgrViewEntryScreen

        selected_menu_num = self.run_screen(
            PwmgrViewEntryScreen,
            page_num=self.page_num,
            title = self.title
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            if self.page_num == 0:
                del self.controller.pwmgr_data["paged_message"]
                del self.controller.pwmgr_data["formatted_entry"]
                return Destination(BackStackView)
            else:
                return Destination(PwmgrViewEntryView, view_args=dict(page_num=self.page_num -1, title=self.title), skip_current_view=True)

        # User clicked "Next"
        if self.page_num == len(self.controller.pwmgr_data["paged_message"]) - 1:
            # We've reached the end of the paged message
            del self.controller.pwmgr_data["paged_message"]
            del self.controller.pwmgr_data["formatted_entry"]
            return Destination(BackStackView)
        else:
            return Destination(PwmgrViewEntryView, view_args=dict(page_num=self.page_num + 1, title=self.title), skip_current_view=True)



class PwmgrGeneratePassLengthView(View):
    MIN_LENGTH=8
    MAX_LENGTH=20

    def __init__(self):
        super().__init__()
        self.controller.resume_main_flow = None
        self.character_list = string.ascii_letters + string.digits + string.punctuation


    def generate_password_from_bytes(self, entropy: bytes, password_length: int) -> str:
        bpw = math.log(len(self.character_list), 2)
        num_bits = bpw * password_length

        password=""
        n = len(self.character_list)
        i = int.from_bytes(entropy, 'big', signed=False)
        while i>0 and len(password) < password_length:
            x = i % n
            i = i//n
            password += self.character_list[x]

        return password


    def run(self):
        button_data = []
        length_range = range(self.MIN_LENGTH, self.MAX_LENGTH+1)
        for i in length_range:
            button_data.append(str(i))

        selected_menu_num = ButtonListScreen(
            title="Password Length?",
            button_data=button_data,
            scroll_y_initial_offset=GUIConstants.BUTTON_HEIGHT * (15-self.MIN_LENGTH),
            selected_button= 15 - self.MIN_LENGTH,
            is_button_text_centered=True,
            is_bottom_list=True,
            show_back_button=False,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        password_length=selected_menu_num+self.MIN_LENGTH

        preview_images = self.controller.image_entropy_preview_frames
        seed_entropy_image = self.controller.image_entropy_final_image

        # Build in some hardware-level uniqueness via CPU unique Serial num
        try:
            stream = os.popen("cat /proc/cpuinfo | grep Serial")
            output = stream.read()
            serial_num = output.split(":")[-1].strip().encode('utf-8')
            serial_hash = hashlib.sha256(serial_num)
            hash_bytes = serial_hash.digest()
        except Exception as e:
            logger.info(repr(e), exc_info=True)
            hash_bytes = b'0'

        # Build in modest entropy via millis since power on
        millis_hash = hashlib.sha256(hash_bytes + str(time.time()).encode('utf-8'))
        hash_bytes = millis_hash.digest()

        # Build in better entropy by chaining the preview frames
        for frame in preview_images:
            img_hash = hashlib.sha256(hash_bytes + frame.tobytes())
            hash_bytes = img_hash.digest()

        # Finally build in our headline entropy via the new full-res image
        final_hash = hashlib.sha256(hash_bytes + seed_entropy_image.tobytes()).digest()

        # Generate the password
        password = self.generate_password_from_bytes(final_hash, password_length)

        # Image should never get saved nor stick around in memory
        seed_entropy_image = None
        preview_images = None
        final_hash = None
        hash_bytes = None
        self.controller.image_entropy_preview_frames = None
        self.controller.image_entropy_final_image = None

        entry = self.controller.pwmgr_data['pwmgr_dict']['entries'][self.controller.pwmgr_data['selected_index']]
        entry['Pass'] = password

        # don't return back to camera preview
        self.controller.pop_prev_from_back_stack()
        self.controller.pwmgr_data['formatted_entry'] = "New Pass:\n" + password
        return Destination(PwmgrViewEntryView)
