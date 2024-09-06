// Copyright (c) 2022-2024, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include "version.h"
#include "device_sidekick.hpp"
#include "int-util.h"
#include "crypto/wallet/crypto.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/subaddress_index.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "ringct/rctOps.h"
#include "cryptonote_config.h"
#include "string_tools.h"
#include "assert.h"
#include <sstream>
#include "memwipe.h"
#include "common/varint.h"

namespace std {
    inline std::ostream &operator<<(std::ostream &o, const crypto::ec_scalar &v) {
        epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
    }
    inline std::ostream &operator<<(std::ostream &o, const crypto::ec_point &v) {
        epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
    }
    inline std::ostream &operator<<(std::ostream &o, const crypto::chacha_key &v) {
        epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
    }
}

static const crypto::hash8 null_payment_id{};

namespace hw {

    namespace sidekick {

        template <class T>
        void execute(std::string& res, const std::string& req, sidekick& device) {
            T cmd(req, device);
            res = cmd.executeAndSerialize(device);
        }

        bool sidekick::check_state(const int commandId) {
            LOG_PRINT_L3(">>> "<<sig_mode<<"."<<tx_in_progress<< " " <<std::hex<<last_command<<" => "<<commandId);
            switch (commandId) {
            // low-level commands - these are always allowed
            case ResetCommand::ID: //5A INS_RESET
            case VerifyKeysCommand::ID: //48 INS_VERIFY_KEY
            case GenerateChachaKeyCommand::ID: //41 INS_GET_CHACHA8_PREKEY
            case GetPublicKeysCommand::ID: //42 INS_GET_KEY(p1=1)
            case GetSecretKeysCommand::ID: //43 INS_GET_KEY(p1=2)
            case DisplayAddressCommand::ID: //61 INS_DISPLAY_ADDRESS
            case GenerateKeyDerivationCommand::ID: //4D INS_GEN_KEY_DERIVATION
            case DerivationToScalarCommand::ID: //4E INS_DERIVATION_TO_SCALAR
            case DeriveSecretKeyCommand::ID: //4F INS_DERIVE_SECRET_KEY
            case DerivePublicKeyCommand::ID: //50 INS_DERIVE_PUBLIC_KEY
            case DeriveSubaddressPublicKeyCommand::ID: //45 INS_DERIVE_SUBADDRESS_PUBLIC_KEY
            case GetSubaddressSpendPublicKeyCommand::ID: //46 INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY
            case GetSubaddressSecretKeyCommand::ID: //47 INS_GET_SUBADDRESS_SECRET_KEY
            case GetSubaddressCommand::ID: //5B INS_GET_SUBADDRESS
            case GenerateKeyImageCommand::ID: //52 INS_GEN_KEY_IMAGE
            case GenerateKeysCommand::ID: //4C INS_GENERATE_KEYPAIR
            case SecretToPublicKeyCommand::ID: //51 INS_SECRET_KEY_TO_PUBLIC_KEY
            case ScSecretAddCommand::ID: //4B INS_SECRET_KEY_ADD
            case ScalarmultKeyCommand::ID: //49 INS_SECRET_SCAL_MUL_KEY
            case ScalarmultBaseCommand::ID: //4A INS_SECRET_SCAL_MUL_BASE
            case EdchDecodeCommand::ID: //5C INS_UNBLIND
            case GenerateTxProofCommand::ID: //53 INS_GET_TX_PROOF
            case CloseTxCommand::ID: //55 INS_CLOSE_TX
            case DeriveViewTagCommand::ID: //62 INS_DERIVE_VIEW_TAG
                return true;

            case SetSigModeCommand::ID: //40 INS_SET_SIGNATURE_MODE
                return !tx_in_progress;

            // high-level commands - these have a strict order & other conditions
            case OpenTxCommand::ID: //54 INS_OPEN_TX
                if (last_command != 0) return false;
                break;
            case EncryptPaymentidCommand::ID: //56 INS_STEALTH
                if (tx_in_progress) {
                    if ((last_command != OpenTxCommand::ID) &&
                        (last_command != EncryptPaymentidCommand::ID))
                        return false;
                } else return true; // and don't set last_command
                break;
            case GenerateOutputEphemeralKeysCommand::ID: //57 INS_GEN_TXOUT_KEYS
                if ((last_command != EncryptPaymentidCommand::ID) &&
                    (last_command != GenerateOutputEphemeralKeysCommand::ID) &&
                    (last_command != OpenTxCommand::ID))
                    return false;
                break;
            case GetTxPrefixHashCommand::ID: //44 INS_PREFIX_HASH
                if (last_command != GenerateOutputEphemeralKeysCommand::ID)
                    return false;
                break;
            case GenCommitmentMaskCommand::ID: //58 INS_GEN_COMMITMENT_MASK
                // I don't believe the Ledger docs about the checks here:
                // Ledger protocol 4 has no checks (only v3 has the following)
                if ((last_command != GetTxPrefixHashCommand::ID) &&
                    (last_command != GenCommitmentMaskCommand::ID))
                    return false;
                // the PDF docs also state this (but the code does not support this):
                if (sig_mode != TRANSACTION_CREATE_REAL) return false;
                break;
            case EdchEncodeCommand::ID: //59 INS_BLIND
                if ((sig_mode == TRANSACTION_CREATE_REAL) &&
                    (last_command != GenCommitmentMaskCommand::ID) &&
                    (last_command != EdchEncodeCommand::ID))
                    return false;
                break;
            case PrehashCommand::ID: //60 INS_VALIDATE
                if (last_command != EdchEncodeCommand::ID)
                    return false;
                break;
            case ClsagPrepareCommand::ID: //5D INS_CLSAG(p1=1)
                if ((last_command != PrehashCommand::ID) &&
                    (last_command != ClsagSignCommand::ID))
                    return false;
                break;
            case ClsagHashCommand::ID: //5E INS_CLSAG(p1=2)
                if ((last_command != ClsagPrepareCommand::ID) &&
                    (last_command != ClsagHashCommand::ID))
                    return false;
                break;
            case ClsagSignCommand::ID: //5F INS_CLSAG(p1=3)
                if (last_command != ClsagHashCommand::ID)
                    return false;
                break;
            default:
                return false;
             }
             CHECK_AND_ASSERT_THROW_MES(tx_in_progress || (commandId==OpenTxCommand::ID), "no tx in progress");
             last_command = commandId;
            return true;
        }

        void sidekick::dispatch(std::string& res, const int commandId, const std::string& req) {
            if (!check_state(commandId)) {
                RcResponse rc;
                rc.rc = RC_FORBIDDEN;
                res = rc.serialize();
                return;
                // TODO lock device
            }
            switch (commandId) {
            case SetSigModeCommand::ID:
                execute<SetSigModeCommand>(res, req, *this);
                break;
            case GenerateChachaKeyCommand::ID:
                execute<GenerateChachaKeyCommand>(res, req, *this);
                break;
            case GetPublicKeysCommand::ID:
                execute<GetPublicKeysCommand>(res, req, *this);
                break;
            case GetSecretKeysCommand::ID:
                execute<GetSecretKeysCommand>(res, req, *this);
                break;
            case DisplayAddressCommand::ID:
                execute<DisplayAddressCommand>(res, req, *this);
                break;
            case DeriveSubaddressPublicKeyCommand::ID:
                execute<DeriveSubaddressPublicKeyCommand>(res, req, *this);
                break;
            case GetSubaddressSpendPublicKeyCommand::ID:
                execute<GetSubaddressSpendPublicKeyCommand>(res, req, *this);
                break;
            case GetSubaddressSecretKeyCommand::ID:
                execute<GetSubaddressSecretKeyCommand>(res, req, *this);
                break;
            case GetSubaddressCommand::ID:
                execute<GetSubaddressCommand>(res, req, *this);
                break;
            case VerifyKeysCommand::ID:
                execute<VerifyKeysCommand>(res, req, *this);
                break;
            case ScalarmultKeyCommand::ID:
                execute<ScalarmultKeyCommand>(res, req, *this);
                break;
            case ScalarmultBaseCommand::ID:
                execute<ScalarmultBaseCommand>(res, req, *this);
                break;
            case ScSecretAddCommand::ID:
                execute<ScSecretAddCommand>(res, req, *this);
                break;
            case GenerateKeysCommand::ID:
                execute<GenerateKeysCommand>(res, req, *this);
                break;
            case GenerateKeyDerivationCommand::ID:
                execute<GenerateKeyDerivationCommand>(res, req, *this);
                break;
            case DerivationToScalarCommand::ID:
                execute<DerivationToScalarCommand>(res, req, *this);
                break;
            case DeriveSecretKeyCommand::ID:
                execute<DeriveSecretKeyCommand>(res, req, *this);
                break;
            case DerivePublicKeyCommand::ID:
                execute<DerivePublicKeyCommand>(res, req, *this);
                break;
            case SecretToPublicKeyCommand::ID:
                execute<SecretToPublicKeyCommand>(res, req, *this);
                break;
            case GenerateKeyImageCommand::ID:
                execute<GenerateKeyImageCommand>(res, req, *this);
                break;
            case GenerateTxProofCommand::ID:
                execute<GenerateTxProofCommand>(res, req, *this);
                break;
            case OpenTxCommand::ID:
                execute<OpenTxCommand>(res, req, *this);
                break;
            case GetTxPrefixHashCommand::ID:
                execute<GetTxPrefixHashCommand>(res, req, *this);
                break;
            case EncryptPaymentidCommand::ID:
                execute<EncryptPaymentidCommand>(res, req, *this);
                break;
            case GenerateOutputEphemeralKeysCommand::ID:
                execute<GenerateOutputEphemeralKeysCommand>(res, req, *this);
                break;
            case GenCommitmentMaskCommand::ID:
                execute<GenCommitmentMaskCommand>(res, req, *this);
                break;
            case EdchEncodeCommand::ID:
                execute<EdchEncodeCommand>(res, req, *this);
                break;
            case EdchDecodeCommand::ID:
                execute<EdchDecodeCommand>(res, req, *this);
                break;
            case ClsagPrepareCommand::ID:
                execute<ClsagPrepareCommand>(res, req, *this);
                break;
            case ClsagHashCommand::ID:
                execute<ClsagHashCommand>(res, req, *this);
                break;
            case ClsagSignCommand::ID:
                execute<ClsagSignCommand>(res, req, *this);
                break;
            case CloseTxCommand::ID:
                execute<CloseTxCommand>(res, req, *this);
                break;
            case ResetCommand::ID:
                execute<ResetCommand>(res, req, *this);
                break;
            case PrehashCommand::ID:
                execute<PrehashCommand>(res, req, *this);
                break;
            default:
                ASSERT_MES_AND_THROW("unknown command " << commandId);
             }
         }

        sidekick::sidekick(cryptonote::network_type networkType, std::string a, std::string b) {
            this->networkType = networkType;
            epee::string_tools::hex_to_pod(a, this->device_keys.m_spend_secret_key);
            epee::string_tools::hex_to_pod(b, this->device_keys.m_view_secret_key);
            crypto::secret_key_to_public_key(this->device_keys.m_spend_secret_key, this->device_keys.m_account_address.m_spend_public_key);
            crypto::secret_key_to_public_key(this->device_keys.m_view_secret_key, this->device_keys.m_account_address.m_view_public_key);
//            LOG_PRINT_L3("secret view  a=" << this->device_keys.m_view_secret_key);
//            LOG_PRINT_L3("secret spend b=" << this->device_keys.m_spend_secret_key);
            LOG_PRINT_L3("public view  A=" << this->device_keys.m_account_address.m_view_public_key);
            LOG_PRINT_L3("public spend B=" << this->device_keys.m_account_address.m_spend_public_key);
        }
//TODO
#define WITH_SIDEKICK 1
#ifdef WITH_SIDEKICK

        /* ===================================================================== */
        /* ===                        Keymap                                ==== */
        /* ===================================================================== */

        sidekick::ABPkeys::ABPkeys(const crypto::public_key& A, const crypto::public_key& B, const bool is_subaddr, const bool is_change, const rct::key& P, const rct::key& AK) {
            Aout = A;
            Bout = B;
            is_subaddress = is_subaddr;
            is_change_address = is_change;
            Pout = P;
            AKout = AK;
        }

        sidekick::ABPkeys::ABPkeys(const ABPkeys& keys) {
            Aout = keys.Aout;
            Bout = keys.Bout;
            is_subaddress = keys.is_subaddress;
            is_change_address = keys.is_change_address;
            Pout = keys.Pout;
            AKout = keys.AKout;
        }

        sidekick::ABPkeys &sidekick::ABPkeys::operator=(const ABPkeys& keys) {
            if (&keys == this)
                return *this;
            Aout = keys.Aout;
            Bout = keys.Bout;
            is_subaddress = keys.is_subaddress;
            is_change_address = keys.is_change_address;
            Pout = keys.Pout;
            AKout = keys.AKout;
            return *this;
        }

        /* ===================================================================== */
        /* ===                        Misc                                ==== */
        /* ===================================================================== */
        static inline unsigned char *operator &(crypto::ec_scalar &scalar) {
            return &reinterpret_cast<unsigned char &>(scalar);
        }
        static inline const unsigned char *operator &(const crypto::ec_scalar &scalar) {
            return &reinterpret_cast<const unsigned char &>(scalar);
        }

        static bool is_fake_view_key(const crypto::secret_key &sec) {
            return memcmp(sec.data, FAKE_SECRET_VIEW_KEY, 32) == 0;
        }

        bool operator==(const crypto::key_derivation &d0, const crypto::key_derivation &d1) {
            static_assert(sizeof(crypto::key_derivation) == 32, "key_derivation must be 32 bytes");
            return !crypto_verify_32((const unsigned char*)&d0, (const unsigned char*)&d1);
        }

        /* ===================================================================== */
        /* ===                             Device                           ==== */
        /* ===================================================================== */

        static int device_id = 0;
        // logic corresponds to Ledger Protocol Version 4
        #define PROTOCOL_VERSION 4

        void sidekick::reset_tx() {
            this->r = crypto::secret_key{};
            this->R = crypto::public_key{};
            this->tx_in_progress = false;
            this->last_command = 0;
            this->alpha = rct::key{};
            this->prefixH = crypto::hash{};
            this->last_get_subaddress_secret_key = crypto::secret_key{};
            this->last_derive_secret_key = crypto::secret_key{};
            this->ABP.clear();
        }

        void sidekick::reset() {
            reset_tx();
            this->sig_mode = TRANSACTION_CREATE_FAKE;
            this->c = rct::key{};
            this->last_get_subaddress_secret_key = crypto::secret_key{};
            this->last_derive_secret_key = crypto::secret_key{};
            this->scalars.clear();
            this->scalar_types.clear();
        }
        uint8_t sidekick::reset(ResetCommand &cmd) {
            // private & public keys are set in constructor (0=>device_keys)
            LOG_PRINT_L3(">=reset MONERO_VERSION=" << cmd.req.version);
            this->reset();
            cmd.res.version = 1<<16; // 0.1.0.0 - TODO yes, this should be a contanr somewhere
            LOG_PRINT_L3("<=reset sidekick=" << cmd.res.version);
            return RC_OK;
        }
        // helper method to disassamble the MONERO_VERSION string into a uint32
        // possible 2k problem in this method
        // each version component must be <= 255
        uint32_t monero_version() {
            uint32_t v = 0;
            std::stringstream ss;
            ss << MONERO_VERSION << '.';
            char buf[4];
            for (size_t i = 0; i < 4; i++){
                ss.getline(buf, 3, '.');
                if (ss.fail()) return 0;
                v = v << 8 | std::atoi(buf);
            }
            return true;
        }

#define MAGIC_ENC (0xAB)
        // called by sidekick to encrypt secret keys
        void sidekick::encrypt(unsigned char* data, field_type type) {
            crypto::ec_scalar s;
            memcpy(s.data, data, 32); // for output:
            LOG_PRINT_L3("encrypt " << s);
            if (type == field_type::KEY) {
                if (!memcmp(data, this->device_keys.m_view_secret_key.data, 32)) {
                    memset(data, 0x00, 32);
                } else if (!memcmp(data, this->device_keys.m_spend_secret_key.data, 32)) {
                    memset(data, 0xFF, 32);
                } else {
                    ASSERT_MES_AND_THROW("expecting a secret key"); // TODO throw a protocol error
                }
            } else {
                size_t idx = scalars.size();
                CHECK_AND_ASSERT_THROW_MES(idx<=0xffffffff, "it's just too much");
                rct::key k;
                memcpy(k.bytes, data, 32);
                if (type == field_type::ALPHA) {
                    alpha = k;
                }
                scalars.push_back(k);
                field_type t = tx_in_progress?type:field_type::SCALAR;
                scalar_types.push_back(t);
                memset(data, 0, 32);
                data[0]  =      idx  & 0xff;
                data[1]  = (idx>>8)  & 0xff;
                data[2]  = (idx>>16) & 0xff;
                data[3]  = (idx>>24) & 0xff;
                data[30] =   (uint8_t) t;
                data[31] = MAGIC_ENC;
            }
            memcpy(s.data, data, 32); // for output:
            LOG_PRINT_L3("encrypted " << s);
        }
        // called by sidekick to decrypt secret keys
        void sidekick::decrypt(unsigned char* data, field_type type) const {
            rct::key s;
            memcpy(s.bytes, data, 32);
            LOG_PRINT_L3("decrypt " << s);
            const unsigned char* p = nullptr;

            if (type == field_type::KEY) {
                if (!memcmp(data, FAKE_SECRET_VIEW_KEY, 32)) {
                    p = (unsigned char*) this->device_keys.m_view_secret_key.data;
                } else if (!memcmp(data, FAKE_SECRET_SPEND_KEY, 32)) {
                    p = (unsigned char*) this->device_keys.m_spend_secret_key.data;
                } else if (!memcmp(data, this->device_keys.m_view_secret_key.data, 32)) {
                    LOG_PRINT_L3("decrypted real_view_key");
                    return;
                } else {
                    type = field_type::SCALAR;
                    LOG_PRINT_L3("NOTAKEY "<<s);
                }
            } else if (type == field_type::VIEWKEY) {
                CHECK_AND_ASSERT_THROW_MES(memcmp(data, FAKE_SECRET_SPEND_KEY, 32), "fake secret spend key not allowed here"); // TODO throw a protocol error
                if (!memcmp(data, FAKE_SECRET_VIEW_KEY, 32)) {
                    p = (unsigned char*) this->device_keys.m_view_secret_key.data;
                } else if (!memcmp(data, this->device_keys.m_view_secret_key.data, 32)) {
                    LOG_PRINT_L3("decrypted real_view_key");
                    return;
                } else {
                    type = field_type::SCALAR;
                    LOG_PRINT_L3("NOTAKEYVIEW "<<s);
                }
            }
            if (p == nullptr) { // decrypt other stuff
                CHECK_AND_ASSERT_THROW_MES(data[31] == MAGIC_ENC, "invalid encrypted");
                field_type t = tx_in_progress?type:field_type::SCALAR;
                CHECK_AND_ASSERT_THROW_MES(data[30] == t, "type mismatch(1)");
                size_t idx = data[0] + (data[1] << 8) + (data[2] << 16) + (data[3] << 24);
                CHECK_AND_ASSERT_THROW_MES(idx<scalars.size(), "invalid idx " << idx);
                CHECK_AND_ASSERT_THROW_MES(scalar_types[idx] == t, "type mismatch(2)");
                if (type == field_type::ALPHA) {
                    CHECK_AND_ASSERT_THROW_MES(scalars[idx] == alpha, "ALPHA does not match (d)");
                }
                LOG_PRINT_L3("decrypted idx " << idx);
                p = scalars[idx].bytes;
                memcpy(s.bytes, p, 32); // for log output

                // sanity checks
                switch (type) {
                case field_type::SCALAR:
                    CHECK_AND_ASSERT_THROW_MES(!sc_check(p), "bad decrypted scalar (range) " << s); // TODO lock devices
                    break;
                case field_type::AMOUNT_KEY:
                case field_type::DERIVATION:
                case field_type::ALPHA:
                    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(p), "bad decrypted scalar (zero)"); // TODO lock devices
                    break;
                default:
                    ASSERT_MES_AND_THROW("invalid type " << type);
                }
            }

            memcpy(data, p, 32);
            LOG_PRINT_L3("decrypted " << s);
        }

        /* ======================================================================= */
        /*                              SETUP/TEARDOWN                             */
        /* ======================================================================= */

        uint8_t sidekick::set_mode(SetSigModeCommand &cmd) {
            LOG_PRINT_L3(">=set_mode " << cmd.req.sig_mode);
            switch (cmd.req.sig_mode) {
                case TRANSACTION_CREATE_REAL:
                case TRANSACTION_CREATE_FAKE:
                    this->sig_mode = (sidekick_mode) cmd.req.sig_mode;
                    break;
                default:
                    return RC_NOK;
            }
            cmd.res.sig_mode = this->sig_mode;
            LOG_PRINT_L3("<=set_mode " << this->sig_mode);
            return RC_OK;
        }

        /* ======================================================================= */
        /*                             WALLET & ADDRESS                            */
        /* ======================================================================= */

        uint8_t sidekick::generate_chacha_key(GenerateChachaKeyCommand &cmd) {
            LOG_PRINT_L3(">=generate_chacha_key " << cmd.req.kdf_rounds);
            // references to make the following code easier to read
            const crypto::secret_key &view_key = this->device_keys.m_view_secret_key;
            const crypto::secret_key &spend_key = this->device_keys.m_spend_secret_key;

            epee::mlocked<tools::scrubbed_arr<char, sizeof(view_key) + sizeof(spend_key) + 1>> data;
            memcpy(data.data(), &view_key, sizeof(view_key));
            memcpy(data.data() + sizeof(view_key), &spend_key, sizeof(spend_key));
            data[sizeof(data) - 1] = config::HASH_KEY_WALLET;
            crypto::generate_chacha_key(data.data(), sizeof(data), cmd.res.key, cmd.req.kdf_rounds);
            LOG_PRINT_L3("<=generate_chacha_key " << cmd.res.key);
            return RC_OK;
        }

        uint8_t sidekick::get_public_address(GetPublicKeysCommand &cmd) {
            LOG_PRINT_L3(">=get_public_address");
            cmd.res.pubkey.m_view_public_key = this->device_keys.m_account_address.m_view_public_key;
            cmd.res.pubkey.m_spend_public_key = this->device_keys.m_account_address.m_spend_public_key;
            return RC_OK;
            LOG_PRINT_L3("<=get_public_address " <<cmd.res.pubkey.m_view_public_key<<cmd.res.pubkey.m_spend_public_key);
        }

        uint8_t sidekick::get_secret_keys(GetSecretKeysCommand &cmd) {
            LOG_PRINT_L3(">=get_secret_keys");
            //secret keys are represented as fake key on the wallet side
            //CALL ()
            cmd.res.spendkey = this->device_keys.m_spend_secret_key;
            cmd.res.viewkey = this->device_keys.m_view_secret_key;
            // TODO: user confirmation
            cmd.res.send_viewkey = true;
            LOG_PRINT_L3("<=get_secret_keys " <<cmd.res.viewkey<<cmd.res.spendkey);
            return RC_OK;
        }

        // TODO implement this
        uint8_t sidekick::display_address(DisplayAddressCommand &cmd) {
            LOG_PRINT_L3(">=device_display_address");
            // TODO: do something with the req
            // e.g. log it:
            if (cmd.req.payment_id != null_payment_id) {
                LOG_PRINT_L3("COMMAND_DISPLAY_ADDRESS " << cmd.req.index.major << "." << cmd.req.index.minor << " " << cmd.req.payment_id);
            } else {
                LOG_PRINT_L3("COMMAND_DISPLAY_ADDRESS " << cmd.req.index.major << "." << cmd.req.index.minor);
            }
            LOG_PRINT_L3("<=device_display_address");
            return RC_OK;
        }

        /* ======================================================================= */
        /*                               SUB ADDRESS                               */
        /* ======================================================================= */

        uint8_t sidekick::derive_subaddress_public_key(DeriveSubaddressPublicKeyCommand &cmd) {
            LOG_PRINT_L3(">=derive_subaddress_public_key " <<cmd.req.out_key<<cmd.req.derivation<<" "<<cmd.req.output_index);
            bool r =
                crypto::wallet::derive_subaddress_public_key(cmd.req.out_key, cmd.req.derivation, cmd.req.output_index, cmd.res.derived_key);
            LOG_PRINT_L3("<=derive_subaddress_public_key " <<cmd.res.derived_key);
            return r?RC_OK:RC_NOK;
        }

        crypto::public_key sidekick::get_subaddress_spend_public_key(cryptonote::subaddress_index index) {
            // m = Hs("SubAddr" || a || index_major || index_minor)
            crypto::secret_key m = get_subaddress_secret_key(index);
            // M = m*G
            crypto::public_key M;
            crypto::secret_key_to_public_key(m, M);
            // D = B + M
            return rct::rct2pk(rct::addKeys(rct::pk2rct(this->device_keys.m_account_address.m_spend_public_key), rct::pk2rct(M)));
        }
        uint8_t sidekick::get_subaddress_spend_public_key(GetSubaddressSpendPublicKeyCommand &cmd) {
            LOG_PRINT_L3(">=device_get_subaddress_spend_public_key " <<cmd.req.index);
            cmd.res.D = get_subaddress_spend_public_key(cmd.req.index);
            LOG_PRINT_L3("<=device_get_subaddress_spend_public_key " <<cmd.res.D);
            return RC_OK;
        }

        uint8_t sidekick::get_subaddress(GetSubaddressCommand &cmd) {
            LOG_PRINT_L3(">=get_subaddress " <<cmd.req.index);
            cmd.res.D = get_subaddress_spend_public_key(cmd.req.index);
            // C = a*D
            cmd.res.C = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(cmd.res.D), rct::sk2rct(this->device_keys.m_view_secret_key)));
            LOG_PRINT_L3("<=get_subaddress " <<cmd.res.C<<cmd.res.D);
            return RC_OK;
        }

        crypto::secret_key sidekick::get_subaddress_secret_key(const cryptonote::subaddress_index &index) {
            LOG_PRINT_L3(">=get_subaddress_secret_key(x) " <<index);
            // m = Hs("SubAddr" || sec || index_major || index_minor)
            // CALL/S (sec/S, index)
            char data[sizeof(config::HASH_KEY_SUBADDRESS) + sizeof(crypto::secret_key) + 2 * sizeof(uint32_t)];
            memcpy(data, config::HASH_KEY_SUBADDRESS, sizeof(config::HASH_KEY_SUBADDRESS));
            // sec may be view or spend i guess?
            memcpy(data + sizeof(config::HASH_KEY_SUBADDRESS), &this->device_keys.m_view_secret_key, sizeof(crypto::secret_key));
            uint32_t idx = SWAP32LE(index.major);
            memcpy(data + sizeof(config::HASH_KEY_SUBADDRESS) + sizeof(crypto::secret_key), &idx, sizeof(uint32_t));
            idx = SWAP32LE(index.minor);
            memcpy(data + sizeof(config::HASH_KEY_SUBADDRESS) + sizeof(crypto::secret_key) + sizeof(uint32_t), &idx, sizeof(uint32_t));
            crypto::secret_key m;
            crypto::hash_to_scalar(data, sizeof(data), m);
            LOG_PRINT_L3("<=get_subaddress_secret_key(x) " << m);
            return m;
        }
        uint8_t sidekick::get_subaddress_secret_key(GetSubaddressSecretKeyCommand &cmd) {
            LOG_PRINT_L3(">=get_subaddress_secret_key " << cmd.req.index);
            cmd.res.m = get_subaddress_secret_key(cmd.req.index);
            this->last_get_subaddress_secret_key = cmd.res.m; // must be s2 in sc_add
            LOG_PRINT_L3("<=get_subaddress_secret_key " <<cmd.res.m);
            return RC_OK;
        }

        /* ======================================================================= */
        /*                            DERIVATION & KEY                             */
        /* ======================================================================= */

        uint8_t sidekick::verify_keys(VerifyKeysCommand &cmd) {
            LOG_PRINT_L3(">=verify_keys " <<cmd.req.sec<<cmd.req.pub);
            // verify spend_secret => spend_public or view_secret => view_public
            // CALL (secret_key/S, public_key)
            crypto::public_key calculated_pub;
            bool r = crypto::secret_key_to_public_key(cmd.req.sec, calculated_pub);
            cmd.res.verified = r && (cmd.req.pub == calculated_pub);
            LOG_PRINT_L3("<=verify_keys " <<cmd.res.verified);
            return RC_OK;
        }

        uint8_t sidekick::scalarmultKey(ScalarmultKeyCommand &cmd) {
            LOG_PRINT_L3(">=scalarmultKey " << cmd.req.a << cmd.req.P);
            rct::scalarmultKey(cmd.res.aP, cmd.req.P, cmd.req.a);
            LOG_PRINT_L3("<=scalarmultKey " << cmd.res.aP);
            return RC_OK;
        }

        uint8_t sidekick::scalarmultBase(ScalarmultBaseCommand &cmd) {
            LOG_PRINT_L3(">=scalarmultBase " << cmd.req.a);
            rct::scalarmultBase(cmd.res.aG, cmd.req.a);
            LOG_PRINT_L3("<=scalarmultBase " <<cmd.res.aG);
            return RC_OK;
        }

        uint8_t sidekick::sc_secret_add(ScSecretAddCommand &cmd) {
            LOG_PRINT_L3(">=sc_secret_add tx_in_progress=" << this->tx_in_progress << " ab="<<cmd.req.a<<cmd.req.b);
            if (this->tx_in_progress) {
                // During a transaction, only "last_derive_secret_key+last_get_subaddress_secret_key"
                // is allowed, in order to match the call at
                // https://github.com/monero-project/monero/blob/f6e63ef260e795aacd408c28008398785b84103a/src/cryptonote_basic/cryptonote_format_utils.cpp#L345
                if ((cmd.req.a != this->last_derive_secret_key) || (cmd.req.b != this->last_get_subaddress_secret_key))
                    return RC_NOK;
            }
            sc_add(&cmd.res.rr, &cmd.req.a, &cmd.req.b);
            LOG_PRINT_L3("<=sc_secret_add " << cmd.res.rr);
            return RC_OK;
        }

        crypto::secret_key sidekick::generate_keys(crypto::public_key &pub, crypto::secret_key &sec) {
            LOG_PRINT_L3("==generate_keys");
            return crypto::generate_keys(pub, sec);
        }
        uint8_t sidekick::generate_keys(GenerateKeysCommand &cmd) {
            LOG_PRINT_L3(">=generate_keys");
            cmd.res.rng = generate_keys(cmd.res.pub, cmd.res.sec);
            LOG_PRINT_L3("<=generate_keys " <<cmd.res.pub<<cmd.res.sec<<cmd.res.rng);
            return RC_OK;
        }

        bool sidekick::generate_key_derivation(const crypto::public_key &tx_pub, const crypto::secret_key &sec_view, crypto::key_derivation &derivation) {
            return crypto::wallet::generate_key_derivation(tx_pub, sec_view, derivation);
        }
        uint8_t sidekick::generate_key_derivation(GenerateKeyDerivationCommand &cmd) {
            return
                generate_key_derivation(cmd.req.tx_pub, this->device_keys.m_view_secret_key, cmd.res.derivation)
                ?RC_OK:RC_NOK;
        }

        void sidekick::derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res) {
            crypto::derivation_to_scalar(derivation, output_index, res);
        }
        uint8_t sidekick::derivation_to_scalar(DerivationToScalarCommand &cmd) {
            LOG_PRINT_L3(">=derivation_to_scalar " <<cmd.req.derivation <<" "<<cmd.req.output_index);
            derivation_to_scalar(cmd.req.derivation, cmd.req.output_index, cmd.res.scalar);
            LOG_PRINT_L3("<=derivation_to_scalar " <<cmd.res.scalar);
            return RC_OK;
        }

        uint8_t sidekick::derive_secret_key(DeriveSecretKeyCommand &cmd) {
            LOG_PRINT_L3(">=derive_secret_key " <<cmd.req.derivation<< cmd.req.output_index<< cmd.req.base);
            crypto::derive_secret_key(cmd.req.derivation, cmd.req.output_index, cmd.req.base, cmd.res.derived_key);
            this->last_derive_secret_key = cmd.res.derived_key;
            LOG_PRINT_L3("<=derive_secret_key " <<cmd.res.derived_key);
            return RC_OK;
        }

        bool sidekick::derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &base, crypto::public_key &derived_key) {
            return crypto::derive_public_key(derivation, output_index, base, derived_key);
        }
        uint8_t sidekick::derive_public_key(DerivePublicKeyCommand &cmd) {
            LOG_PRINT_L3(">=derive_public_key " <<cmd.req.derivation<< cmd.req.output_index<< cmd.req.base);
            bool r =
                crypto::derive_public_key(cmd.req.derivation, cmd.req.output_index, cmd.req.base, cmd.res.derived_key);
            LOG_PRINT_L3("<=derive_public_key " << cmd.res.derived_key);
            return r?RC_OK:RC_NOK;
        }

        uint8_t sidekick::secret_key_to_public_key(SecretToPublicKeyCommand &cmd) {
            LOG_PRINT_L3(">=secret_key_to_public_key " <<cmd.req.sec);
            bool r = crypto::secret_key_to_public_key(cmd.req.sec, cmd.res.pubkey);
            LOG_PRINT_L3("<=secret_key_to_public_key " <<cmd.res.pubkey);
            return r?RC_OK:RC_NOK;
        }

        uint8_t sidekick::generate_key_image(GenerateKeyImageCommand &cmd) {
            LOG_PRINT_L3(">=generate_key_image " <<cmd.req.pub<< cmd.req.sec);
            crypto::generate_key_image(cmd.req.pub, cmd.req.sec, cmd.res.image);
            LOG_PRINT_L3("<=generate_key_image " <<cmd.res.image);
            return RC_OK;
        }

        uint8_t sidekick::derive_view_tag(DeriveViewTagCommand &cmd) {
            LOG_PRINT_L3(">=derive_view_tag " <<cmd.req.derivation <<"/"<< cmd.req.output_index);
            crypto::derive_view_tag(cmd.req.derivation, cmd.req.output_index, cmd.res.view_tag);
            LOG_PRINT_L3("<=derive_view_tag " <<static_cast<int>(cmd.res.view_tag.data));
            return RC_OK;
        }

        /* ======================================================================= */
        /*                               TRANSACTION                               */
        /* ======================================================================= */

        uint8_t sidekick::generate_tx_proof(GenerateTxProofCommand &cmd) {
            LOG_PRINT_L3(">=generate_tx_proof " << cmd.req.prefix_hash
                                 << cmd.req.R
                                 << cmd.req.A
                                 << cmd.req.has_B
                                 << cmd.req.B
                                 << cmd.req.D
                                 << cmd.req.rr);
            boost::optional<crypto::public_key> B;
            if (cmd.req.has_B) B = cmd.req.B;
            crypto::generate_tx_proof(  cmd.req.prefix_hash,
                                        cmd.req.R,
                                        cmd.req.A,
                                        B,
                                        cmd.req.D,
                                        cmd.req.rr,
                                        cmd.res.sig);
            LOG_PRINT_L3("<=generate_tx_proof " << cmd.res.sig);
            return RC_OK;
        }

        uint8_t sidekick::open_tx(OpenTxCommand &cmd) {
            LOG_PRINT_L3(">=open_tx");
            reset_tx();
            last_command = OpenTxCommand::ID;
            this->tx_in_progress = true;
            generate_keys(this->R, this->r);
            cmd.res.tx_key = this->r;
            cmd.res.view_key  = device_keys.m_view_secret_key;
            cmd.res.spend_key = device_keys.m_spend_secret_key;
            LOG_PRINT_L3("<=open_tx " <<cmd.res.tx_key<<cmd.res.view_key<<cmd.res.spend_key);
            return RC_OK;
        }

        uint8_t sidekick::get_transaction_prefix_hash(GetTxPrefixHashCommand &cmd) {
            LOG_PRINT_L3(">=get_transaction_prefix_hash");
            if ((this->sig_mode == TRANSACTION_CREATE_REAL) && (cmd.req.tx_prefix.unlock_time > 0)) {
                LOG_PRINT_L3("USER: unlock_time=" << cmd.req.tx_prefix.unlock_time);
                // TODO: get user to confirm unlock_time
                return RC_DENIED; // unlock time not supported for now
            }
            cryptonote::get_transaction_prefix_hash(cmd.req.tx_prefix, cmd.res.h);
            this->prefixH = cmd.res.h;
            LOG_PRINT_L3("<=get_transaction_prefix_hash " << this->prefixH);
            return RC_OK;
        }

        uint8_t sidekick::encrypt_payment_id(EncryptPaymentidCommand &cmd) {
            LOG_PRINT_L3(">=encrypt_payment_id " <<cmd.req.payment_id<<cmd.req.public_key<<cmd.req.secret_key);
            crypto::key_derivation derivation;
            if (!generate_key_derivation(cmd.req.public_key, cmd.req.secret_key, derivation))
                return RC_NOK;
            char data[33]; /* A hash, and an extra byte */
            memcpy(data, &derivation, 32);
            data[32] = config::HASH_KEY_ENCRYPTED_PAYMENT_ID;
            crypto::hash hash;
            cn_fast_hash(data, 33, hash);

            for (size_t i = 0; i < 8; ++i)
                cmd.res.payment_id.data[i] = cmd.req.payment_id.data[i] ^ hash.data[i];

            LOG_PRINT_L3("<=encrypt_payment_id " << cmd.res.payment_id);
            return RC_OK;
        }

        void sidekick::store_output(const crypto::public_key &Aout, const crypto::public_key &Bout, const bool is_subaddress, const bool is_change,
                                        const crypto::secret_key &amount_key,  const crypto::public_key &out_eph_public_key)  {
            this->ABP.push_back(ABPkeys(Aout, Bout, is_subaddress, is_change, rct::pk2rct(out_eph_public_key), rct::sk2rct(amount_key)));
        }

        uint8_t sidekick::generate_output_ephemeral_keys(GenerateOutputEphemeralKeysCommand &cmd) {
            LOG_PRINT_L3("==generate_output_ephemeral_keys");
            // make additional tx pubkey if necessary
            if (cmd.req.need_additional_tx_key) {
                if (cmd.req.is_subaddress)
                    cmd.res.additional_tx_key_pub = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(cmd.req.Bout), rct::sk2rct(cmd.req.additional_tx_key)));
                else
                    cmd.res.additional_tx_key_pub = rct::rct2pk(rct::scalarmultBase(rct::sk2rct(cmd.req.additional_tx_key)));
            }

             // derivation
            crypto::key_derivation derivation;
            if (cmd.req.is_change) {
                // sending change to yourself; derivation = a*R
                if (!generate_key_derivation(cmd.req.tx_key_pub, this->device_keys.m_view_secret_key, derivation)) {
                    return RC_NOK;
                }
            } else {
                // sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
                if (!generate_key_derivation(
                        cmd.req.Aout,
                        (cmd.req.is_subaddress && cmd.req.need_additional_tx_key) ? cmd.req.additional_tx_key : cmd.req.tx_key, derivation)) {
                    return RC_NOK;
                }
            }

            CHECK_AND_ASSERT_THROW_MES(cmd.req.tx_version > 1, "tx_version not > 1");
            // compute amount key AKout (amount_key), version is always greater than 1
            derivation_to_scalar(derivation, cmd.req.output_index, cmd.res.amount_key);

            // and the out_eph_public_key
            if (!derive_public_key(derivation, cmd.req.output_index, cmd.req.Bout, cmd.res.out_eph_public_key))
                return RC_NOK;

            if (cmd.req.use_view_tags) {
                crypto::derive_view_tag(derivation, cmd.req.output_index, cmd.res.view_tag);
            }

            // add ABPkeys for use in validation stage
            this->store_output( cmd.req.Aout,
                                cmd.req.Bout,
                                cmd.req.is_subaddress,
                                cmd.req.is_change,
                                cmd.res.amount_key,
                                cmd.res.out_eph_public_key);
            return RC_OK;
        }

        uint8_t sidekick::genCommitmentMask(GenCommitmentMaskCommand &cmd) {
            LOG_PRINT_L3(">=genCommitmentMask " << cmd.req.amount_key);
            cmd.res.mask = rct::genCommitmentMask(cmd.req.amount_key);
            LOG_PRINT_L3("<=genCommitmentMask " << cmd.res.mask);
            return RC_OK;
        }

        uint8_t sidekick::ecdhEncode(EdchEncodeCommand &cmd) {
            LOG_PRINT_L3(">=ecdhEncode "<<cmd.req.unmasked.amount<<cmd.req.unmasked.mask<<cmd.req.sharedSec<<cmd.req.is_short_amount);
            rct::ecdhTuple tuple = cmd.req.unmasked;
            rct::ecdhEncode(tuple, cmd.req.sharedSec, cmd.req.is_short_amount);
            cmd.res.masked = tuple;
            LOG_PRINT_L3("<=ecdhEncode "<<cmd.res.masked.amount<<cmd.res.masked.mask);
            return RC_OK;
        }

        uint8_t sidekick::ecdhDecode(EdchDecodeCommand &cmd) {
            LOG_PRINT_L3(">=ecdhDecode " << cmd.req.masked.amount<<cmd.req.masked.mask<<cmd.req.sharedSec<<cmd.req.is_short_amount);
            rct::ecdhTuple tuple = cmd.req.masked;
            rct::ecdhDecode(tuple, cmd.req.sharedSec, cmd.req.is_short_amount);
            cmd.res.unmasked = tuple;
            LOG_PRINT_L3("<=ecdhDecode " << cmd.res.unmasked.amount<<cmd.res.unmasked.mask);
            return RC_OK;
        }

        // get the amuont as uint64_t
        uint64_t xmr_from_amount(const rct::key &amount) {
            uint64_t xmr = 0;
            int i;
            for (i = 7; i >= 0; i--) {
                xmr = xmr * 256 + amount[i];
            }
            return xmr;
        }
        uint8_t sidekick::prehash(PrehashCommand &cmd) {
            LOG_PRINT_L3(">=prehash " <<cmd.req.inputs_size<<","<<cmd.req.outputs_size);
            CHECK_AND_ASSERT_THROW_MES(cmd.req.blob.size() > 0, "blob is empty");
            // check type is supported (type==rct::RCTTypeBulletproofPlus ONLY)
            CHECK_AND_ASSERT_THROW_MES(cmd.req.blob[0] == rct::RCTTypeBulletproofPlus, "TX type not supported: " << std::to_string((uint8_t) cmd.req.blob[0]));

            // verify hash[0] == prefixH
            CHECK_AND_ASSERT_THROW_MES(rct::rct2hash(cmd.req.hashes[0]) == this->prefixH, "message does not match");
            crypto::hash h = crypto::cn_fast_hash(cmd.req.blob.data(), cmd.req.blob.size());
            // verify hash[1] == H(cmd.req.blob)
            CHECK_AND_ASSERT_THROW_MES(cmd.req.hashes[1] == rct::hash2rct(h), "message does not match");
            // hash[2] is the proof - we don't verify that

            int rc = RC_OK;

            if (sig_mode == TRANSACTION_CREATE_REAL) {
                uint64_t tx_fee;
                size_t read = tools::read_varint(cmd.req.blob.begin()+1, cmd.req.blob.end(), tx_fee);
                CHECK_AND_ASSERT_THROW_MES(read>0, "tx_fee parsing failed with " << read);
                std::stringstream transfers;
                // USER confirms tx_fee
                LOG_PRINT_L3("TX_FEE = " << tx_fee << " read=" << read);
                transfers << tx_fee;
                // verify data in cmd.req.blob is good and matches outputs & and let user confirm each
                crypto::hash8 *v = (crypto::hash8*)&cmd.req.blob[1+read];
                rct::key      *C = (rct::key*)&cmd.req.blob[1+read + 8*cmd.req.outputs_size];
                // for each output:
                for (size_t output = 0; output < cmd.req.outputs_size; output++) {
                    // verify P is at same pos in ABP
                    ABPkeys abp = ABP[output]; // we stored these in generate_output_ephemeral_keys
                    CHECK_AND_ASSERT_THROW_MES(cmd.req.outPk[output].dest == abp.Pout, "ephemeral tx key does not match");

                    // unblind k,v
                    rct::ecdhTuple tuple{};
                    memcpy(tuple.amount.bytes, &v[output], 8);
                    LOG_PRINT_L3("pre  = " << tuple.amount << tuple.mask<<abp.AKout);
                    rct::ecdhDecode(tuple, abp.AKout, true); // true = CLSAG
                    LOG_PRINT_L3("post = " << tuple.amount << tuple.mask);

                    // verify C = aH + kG
                    rct::key aH = rct::scalarmultH(tuple.amount);
                    rct::key kG = rct::scalarmultBase(tuple.mask);
                    rct::key C_computed = rct::addKeys(aH, kG);
                    //CHECK_AND_ASSERT_THROW_MES(C[output]==C_computed, "Commitment does not match: " << C[output] << "!=" << C_computed);
                    LOG_PRINT_L3("C: soll" << C[output] << " ist" << C_computed);
                    // USER confirm address & amount
                    cryptonote::account_public_address adr{abp.Bout, abp.Aout}; // relies on order in struct (maybe not a good idea)
                    std::string out_address = get_account_address_as_str(networkType, abp.is_subaddress, adr);
                    LOG_PRINT_L3("ADDRESS = " << out_address);
                    LOG_PRINT_L3("AMOUNT  = " << tuple.amount);
                    transfers << ":" << (abp.is_change_address?"T":"F") << ":" << out_address << ":" << xmr_from_amount(tuple.amount);
                }
                if (!ConfirmTransfers(transfers.str().c_str())) rc = RC_DENIED;
            }

            // all is good - hash the hashes and move on
            cmd.res.prehash = rct::cn_fast_hash(cmd.req.hashes); // take these as they have been verified above
            LOG_PRINT_L3("<=prehash " <<cmd.res.prehash);
            return rc;
        }

        uint8_t sidekick::clsag_prepare(ClsagPrepareCommand &cmd) {
            LOG_PRINT_L3(">=clsag_prepare");
            rct::skpkGen(cmd.res.a, cmd.res.aG); // aG = a*G
            rct::scalarmultKey(cmd.res.aH, cmd.req.H, cmd.res.a); // aH = a*H
            rct::scalarmultKey(cmd.res.I, cmd.req.H, cmd.req.p); // I = p*H
            rct::scalarmultKey(cmd.res.D, cmd.req.H, cmd.req.z); // D = z*H
            LOG_PRINT_L3("<=clsag_prepare");
            return RC_OK;
        }

        uint8_t sidekick::clsag_hash(ClsagHashCommand &cmd) {
            LOG_PRINT_L3(">=clsag_hash");
            cmd.res.hash = rct::hash_to_scalar(cmd.req.data);
            this->c = cmd.res.hash; // store it for later use in clsag_sign()
            LOG_PRINT_L3(">=clsag_hash " << cmd.res.hash);
            return RC_OK;
        }

        // TODO maybe always lock on NOK & inform the user
        uint8_t sidekick::clsag_sign(ClsagSignCommand &cmd) {
            LOG_PRINT_L3(">=clsag_sign");
            CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(cmd.req.a.bytes), "a is ZERO");
            CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(cmd.req.p.bytes), "p is ZERO");
            CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(cmd.req.z.bytes), "z is ZERO");
            if ((this->sig_mode != TRANSACTION_CREATE_FAKE) && (this->sig_mode != TRANSACTION_CREATE_REAL))
                return RC_NOK;

            rct::key s0_p_mu_P;
            sc_mul(s0_p_mu_P.bytes, cmd.req.mu_P.bytes, cmd.req.p.bytes);
            rct::key s0_add_z_mu_C;
            sc_muladd(s0_add_z_mu_C.bytes, cmd.req.mu_C.bytes, cmd.req.z.bytes, s0_p_mu_P.bytes);
            // use our own c which was generated in clsag_hash()
            sc_mulsub(cmd.res.s.bytes, this->c.bytes, s0_add_z_mu_C.bytes, cmd.req.a.bytes);
            LOG_PRINT_L3("<=clsag_sign " <<cmd.res.s);
            return RC_OK;
        }

        uint8_t sidekick::close_tx(CloseTxCommand &cmd) {
            LOG_PRINT_L3(">=close_tx");
            reset_tx();
            LOG_PRINT_L3("<=close_tx");
            return RC_OK;
        }
    #endif //WITH_SIDEKICK

    }

}

namespace Monerujo {
    class SidekickWallet {
    public:
        enum Status {
            Status_Ok,
            Status_Error,
            Status_Critical
        };

        SidekickWallet(uint8_t networkType, std::string a, std::string b, uint64_t restoreheight);

        ~SidekickWallet();

        std::string call(int commandId, const std::string &request);

        void reset();

        Status status() const;

        uint64_t getRestoreheight() const;

    private:
        const uint64_t restoreheight;
        hw::sidekick::sidekick *instance;
    };

    SidekickWallet::SidekickWallet(uint8_t networkType, std::string a, std::string b, uint64_t restoreheight) : restoreheight{restoreheight} {
        instance = new hw::sidekick::sidekick(static_cast<cryptonote::network_type> (networkType), a, b);
    }

    SidekickWallet::~SidekickWallet() {
        delete instance;
    }

    std::string SidekickWallet::call(int commandId, const std::string &request) {
        std::string result;
        instance->dispatch(result, commandId, request);
        return result;
    }

    void SidekickWallet::reset() {
        instance->reset();
    }

    SidekickWallet::Status SidekickWallet::status() const {
        return SidekickWallet::Status::Status_Ok;
    }

    uint64_t SidekickWallet::getRestoreheight() const {
        return restoreheight;
    }
}
