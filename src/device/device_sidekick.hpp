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

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief ConfirmTransfers
 * @param transfers - string of "fee (':' address ':' amount)+"
 *
 * @return true on accept, false on reject
 */
bool ConfirmTransfers(const char* transfers);

#ifdef __cplusplus
}
#endif

#include <fstream>
#include "serialization/serialization.h"
#include "serialization/string.h"
#include <openssl/sha.h>
#include "device.hpp"
#include "log.hpp"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/subaddress_index.h"
#include <vector>

namespace hw {
    namespace sidekick {
        const unsigned char FAKE_SECRET_VIEW_KEY[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        const unsigned char FAKE_SECRET_SPEND_KEY[32] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        template<class T>
        inline bool read(std::istream &is, T &v) {
            char buf[2*sizeof(T)+1];
            is.getline(buf, sizeof(buf), ':');
            if (is.fail()) return false;
            return epee::from_hex::to_buffer(epee::as_mut_byte_span(v), buf);
        }

        template<class T>
        inline bool write(std::ostream &os, T &v) {
            epee::to_hex::buffer(os, epee::as_byte_span(v)); os<<':'; return !os.fail();
        }

        inline bool write(std::ostream &os, crypto::secret_key &v) {
            rct::key k;
            for (size_t i = 0; i < sizeof(rct::key); i++) {
                k[i] = v.data[31-i];
            }
            epee::to_hex::buffer(os, epee::as_byte_span(k)); os<<':'; return !os.fail();
        }

        // some magic return codes
        static const int RC_UNDEF     = -999;
        static const int RC_OK        =    0;
        static const int RC_NOK       =   -1;
        static const int RC_DENIED    =   -2; // by user
        static const int RC_STATE_NOK =  -10; // anything <= than this is a protocol hard error
        static const int RC_FORBIDDEN =  -11; // state machine says no

        enum sidekick_mode {
            TRANSACTION_CREATE_REAL = device::device_mode::TRANSACTION_CREATE_REAL,
            TRANSACTION_CREATE_FAKE = device::device_mode::TRANSACTION_CREATE_FAKE
        };

        std::string BluetoothTransport(std::string data);

        class SetSigModeCommand;
        class GenerateChachaKeyCommand;
        class GetPublicKeysCommand;
        class GetSecretKeysCommand;
        class DisplayAddressCommand;
        class DeriveSubaddressPublicKeyCommand;
        class GetSubaddressSpendPublicKeyCommand;
        class GetSubaddressSecretKeyCommand;
        class GetSubaddressCommand;
        class VerifyKeysCommand;
        class ScalarmultKeyCommand;
        class ScalarmultBaseCommand;
        class ScSecretAddCommand;
        class GenerateKeysCommand;
        class GenerateKeyDerivationCommand;
        class DerivationToScalarCommand;
        class DeriveSecretKeyCommand;
        class DerivePublicKeyCommand;
        class SecretToPublicKeyCommand;
        class GenerateKeyImageCommand;
        class DeriveViewTagCommand;
        class GenerateTxProofCommand;
        class OpenTxCommand;
        class GetTxPrefixHashCommand;
        class EncryptPaymentidCommand;
        class GenerateOutputEphemeralKeysCommand;
        class GenCommitmentMaskCommand;
        class EdchEncodeCommand;
        class EdchDecodeCommand;
        class ClsagPrepareCommand;
        class ClsagHashCommand;
        class ClsagSignCommand;
        class CloseTxCommand;
        class ResetCommand;
        class PrehashCommand;

        struct keys {
            cryptonote::account_public_address m_account_address;
            crypto::secret_key m_spend_secret_key;
            crypto::secret_key m_view_secret_key;
        };

        class sidekick {
        public:
            sidekick(cryptonote::network_type networkType, std::string a, std::string b);
            void init(crypto::secret_key &a, crypto::secret_key &b);
            void dispatch(std::string& res, const int commandId, const std::string& req);
            bool check_state(const int commandId);
            uint8_t set_mode(SetSigModeCommand &cmd);
            uint8_t generate_chacha_key(GenerateChachaKeyCommand &cmd);
            uint8_t get_public_address(GetPublicKeysCommand &cmd);
            uint8_t get_secret_keys(GetSecretKeysCommand &cmd);
            uint8_t display_address(DisplayAddressCommand &cmd);
            uint8_t derive_subaddress_public_key(DeriveSubaddressPublicKeyCommand &cmd);
            uint8_t get_subaddress_spend_public_key(GetSubaddressSpendPublicKeyCommand &cmd);
            uint8_t get_subaddress_secret_key(GetSubaddressSecretKeyCommand &cmd);
            uint8_t get_subaddress(GetSubaddressCommand &cmd);
            uint8_t verify_keys(VerifyKeysCommand &cmd);
            uint8_t scalarmultKey(ScalarmultKeyCommand &cmd);
            uint8_t scalarmultBase(ScalarmultBaseCommand &cmd);
            uint8_t sc_secret_add(ScSecretAddCommand &cmd);
            uint8_t generate_keys(GenerateKeysCommand &cmd);
            uint8_t generate_key_derivation(GenerateKeyDerivationCommand &cmd);
            uint8_t derivation_to_scalar(DerivationToScalarCommand &cmd);
            uint8_t derive_secret_key(DeriveSecretKeyCommand &cmd);
            uint8_t derive_public_key(DerivePublicKeyCommand &cmd);
            uint8_t secret_key_to_public_key(SecretToPublicKeyCommand &cmd);
            uint8_t generate_key_image(GenerateKeyImageCommand &cmd);
            uint8_t derive_view_tag(DeriveViewTagCommand &cmd);
            uint8_t generate_tx_proof(GenerateTxProofCommand &cmd);
            uint8_t open_tx(OpenTxCommand &cmd);
            uint8_t get_transaction_prefix_hash(GetTxPrefixHashCommand &cmd);
            uint8_t encrypt_payment_id(EncryptPaymentidCommand &cmd);
            uint8_t generate_output_ephemeral_keys(GenerateOutputEphemeralKeysCommand &cmd);
            uint8_t genCommitmentMask(GenCommitmentMaskCommand &cmd);
            uint8_t ecdhEncode(EdchEncodeCommand &cmd);
            uint8_t ecdhDecode(EdchDecodeCommand &cmd);
            uint8_t clsag_prepare(ClsagPrepareCommand &cmd);
            uint8_t clsag_hash(ClsagHashCommand &cmd);
            uint8_t clsag_sign(ClsagSignCommand &cmd);
            uint8_t close_tx(CloseTxCommand &cmd);
            uint8_t reset(ResetCommand &cmd);
            uint8_t prehash(PrehashCommand &cmd);

            enum field_type {
                SCALAR,
                DERIVATION,
                AMOUNT_KEY,
                ALPHA, // TODO store tx_sign_cnt as well?
                VIEWKEY, // a SCALAR which could be the fake viewkey
                KEY      // a SCALAR which could be the fake viewkey or spendkey
            };

            void reset();

            void encrypt(unsigned char* data, field_type type);
            void decrypt(unsigned char* data, field_type type) const;

        private:
            static sidekick* instance;

            int last_command = 0;

            cryptonote::network_type networkType;
            keys device_keys{};

            bool tx_in_progress = false;
            sidekick_mode sig_mode = TRANSACTION_CREATE_FAKE;
            crypto::secret_key r{};
            crypto::public_key R{};
            rct::key c{};
            rct::key alpha{};
            crypto::secret_key last_get_subaddress_secret_key{};
            crypto::secret_key last_derive_secret_key{};

            crypto::hash prefixH{};

            crypto::secret_key get_subaddress_secret_key(const cryptonote::subaddress_index &index);
            crypto::secret_key generate_keys(crypto::public_key &pub, crypto::secret_key &sec);
            bool generate_key_derivation(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation);
            void derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res);
            bool derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &base, crypto::public_key &derived_key);
            crypto::public_key get_subaddress_spend_public_key(cryptonote::subaddress_index index);
            void reset_tx();

            class ABPkeys {
            public:
                crypto::public_key Aout;
                crypto::public_key Bout;
                bool     is_subaddress;
                bool     is_change_address;
                rct::key Pout;
                rct::key AKout;
                ABPkeys(const crypto::public_key& A, const crypto::public_key& B, const bool is_subaddr, const bool is_change, const rct::key& P, const rct::key& AK);
                ABPkeys(const ABPkeys& keys) ;
                ABPkeys() {is_subaddress=false;is_change_address=false;}
                ABPkeys &operator=(const ABPkeys &keys);
            };
            std::vector<ABPkeys> ABP;
            void store_output(const crypto::public_key &Aout, const crypto::public_key &Bout, const bool is_subaddress, const bool is_change,
                                const crypto::secret_key &amount_key,  const crypto::public_key &out_eph_public_key);

            std::vector<rct::key> scalars;
            std::vector<field_type> scalar_types;
        };

        struct RcResponse {
            int rc = RC_UNDEF;
            BEGIN_SERIALIZE_OBJECT()
                FIELD(rc)
            END_SERIALIZE()
            std::string serialize() {
                std::stringstream ss;
                binary_archive<true> ba(ss);
                CHECK_AND_ASSERT_THROW_MES(member_do_serialize(ba), "failed to serialize response");
                return ss.str();
            }
        };

        struct Request {
            Request() = default;
            unsigned char commandId;
            int correlationId = -1;
            BEGIN_SERIALIZE_OBJECT()
                FIELD(commandId)
                FIELD(correlationId)
            END_SERIALIZE()
            virtual bool decrypt(const sidekick &device) {return true;}
        };
        struct Response {
            Response() = default;
            int rc = RC_UNDEF;
            int correlationId;
            BEGIN_SERIALIZE_OBJECT()
                FIELD(rc)
                FIELD(correlationId)
            END_SERIALIZE()
            virtual bool encrypt(sidekick &device) {return true;}
        };
        template <class RequestType, class ResponseType, int CID>
        class Command {
        public:
            enum {ID=CID};
            RequestType req;
            ResponseType res;
            Command() {req.commandId = CID;} // TODO: generate correlationId & set it
            Command(const std::string &requestData, const sidekick &device) {
                CHECK_AND_ASSERT_THROW_MES(deserializeRequest(requestData, device), "failed to deserialize");
                res.correlationId = req.correlationId;
            }

            std::string serializeRequest() { // should be const but can't because auf do_serialize impl
                std::stringstream ss;
                binary_archive<true> ba(ss);
                CHECK_AND_ASSERT_THROW_MES(do_serialize(ba, req), "failed to serialize request");
                return ss.str();
            }

            bool deserializeRequest(const std::string &data, const sidekick &device) {
                binary_archive<false> ba{epee::strspan<std::uint8_t>(data)};
                return do_serialize(ba, req) && req.decrypt(device);
            }

            std::string serializeResponse(sidekick &device) {
                res.encrypt(device);
                std::stringstream ss;
                binary_archive<true> ba(ss);
                CHECK_AND_ASSERT_THROW_MES(do_serialize(ba, res), "failed to serialize response");
                return ss.str();
            }

            bool deserializeResponse(const std::string &data) {
                binary_archive<false> ba{epee::strspan<std::uint8_t>(data)};
                return do_serialize(ba, res);
            }

            bool checkResponse(const std::string &data) {
                binary_archive<false> ba{epee::strspan<std::uint8_t>(data)};
                RcResponse res;
                bool r = do_serialize(ba, res);
                LOG_PRINT_L3("RC_CHECK " << r << " " << res.rc);
                return r && (res.rc > RC_STATE_NOK);
            }

            virtual void execute(sidekick &device) = 0;
            std::string executeAndSerialize(sidekick &device) {
                // do stuff
                LOG_PRINT_L3("doing stuff");
                execute(device);
                return serializeResponse(device);
            }
        };

        struct SetSigModeRequest: Request {
            int sig_mode;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(sig_mode)
            END_SERIALIZE()
        };
        struct SetSigModeResponse: Response {
            int sig_mode;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(sig_mode)
            END_SERIALIZE()
        };
        class SetSigModeCommand: public Command<SetSigModeRequest, SetSigModeResponse, 0x40> {
        public:
            SetSigModeCommand(): Command() {};
            SetSigModeCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.set_mode(*this);
            }
        };

        struct GenerateChachaKeyRequest: Request {
            uint64_t kdf_rounds;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(kdf_rounds)
            END_SERIALIZE()
        };
        struct GenerateChachaKeyResponse: Response {
            crypto::chacha_key key;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(key)
            END_SERIALIZE()
        };
        class GenerateChachaKeyCommand: public Command<GenerateChachaKeyRequest, GenerateChachaKeyResponse, 0x41> {
        public:
            GenerateChachaKeyCommand(): Command() {};
            GenerateChachaKeyCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.generate_chacha_key(*this);
            }
        };

        struct GetPublicKeysRequest: Request {
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
            END_SERIALIZE()
        };
        struct GetPublicKeysResponse: Response {
            cryptonote::account_public_address pubkey;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(pubkey)
            END_SERIALIZE()
        };
        class GetPublicKeysCommand: public Command<GetPublicKeysRequest, GetPublicKeysResponse, 0x42> {
        public:
            GetPublicKeysCommand(): Command() {};
            GetPublicKeysCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.get_public_address(*this);
            }
        };

        struct GetSecretKeysRequest: Request {
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
            END_SERIALIZE()
        };
        struct GetSecretKeysResponse:Response {
            crypto::secret_key viewkey;
            crypto::secret_key spendkey;
            bool send_viewkey;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(viewkey)
                FIELD(spendkey)
            END_SERIALIZE()
            bool encrypt(sidekick &device) {
                device.encrypt((unsigned char*) spendkey.data, sidekick::field_type::KEY);
                if (!send_viewkey)
                    device.encrypt((unsigned char*) viewkey.data, sidekick::field_type::KEY);
                return true;
            }
        };
        class GetSecretKeysCommand: public Command<GetSecretKeysRequest, GetSecretKeysResponse, 0x43> {
        public:
            GetSecretKeysCommand(): Command() {};
            GetSecretKeysCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.get_secret_keys(*this);
            }
        };

        struct DisplayAddressRequest: Request {
            cryptonote::subaddress_index index;
            crypto::hash8 payment_id;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(index)
                FIELD(payment_id)
            END_SERIALIZE()
        };
        struct DisplayAddressResponse: Response {
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
            END_SERIALIZE()
        };
        class DisplayAddressCommand: public Command<DisplayAddressRequest, DisplayAddressResponse, 0x61> {
        public:
            DisplayAddressCommand(): Command() {};
            DisplayAddressCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.display_address(*this);
            }
        };

        struct DeriveSubaddressPublicKeyRequest: Request {
            crypto::public_key out_key;
            crypto::key_derivation derivation;
            std::size_t output_index;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(out_key)
                FIELD(derivation)
                FIELD(output_index)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) derivation.data, sidekick::field_type::DERIVATION);
                return true;
            }
        };
        struct DeriveSubaddressPublicKeyResponse: Response {
            crypto::public_key derived_key;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(derived_key)
            END_SERIALIZE()
        };
        class DeriveSubaddressPublicKeyCommand: public Command<DeriveSubaddressPublicKeyRequest, DeriveSubaddressPublicKeyResponse, 0x45> {
        public:
            DeriveSubaddressPublicKeyCommand(): Command() {};
            DeriveSubaddressPublicKeyCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.derive_subaddress_public_key(*this);
            }
        };

        struct GetSubaddressSpendPublicKeyRequest: Request {
            cryptonote::subaddress_index index;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(index)
            END_SERIALIZE()
        };
        struct GetSubaddressSpendPublicKeyResponse: Response {
            crypto::public_key D;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(D)
            END_SERIALIZE()
        };
        class GetSubaddressSpendPublicKeyCommand: public Command<GetSubaddressSpendPublicKeyRequest, GetSubaddressSpendPublicKeyResponse, 0x46> {
        public:
            GetSubaddressSpendPublicKeyCommand(): Command() {};
            GetSubaddressSpendPublicKeyCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.get_subaddress_spend_public_key(*this);
            }
        };

        struct GetSubaddressSecretKeyRequest: Request {
            cryptonote::subaddress_index index;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(index)
            END_SERIALIZE()
        };
        struct GetSubaddressSecretKeyResponse: Response {
            crypto::secret_key m;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(m)
            END_SERIALIZE()
            bool encrypt(sidekick &device) {
                device.encrypt((unsigned char*) m.data, sidekick::field_type::SCALAR);
                return true;
            }
        };
        class GetSubaddressSecretKeyCommand: public Command<GetSubaddressSecretKeyRequest, GetSubaddressSecretKeyResponse, 0x47> {
        public:
            GetSubaddressSecretKeyCommand(): Command() {};
            GetSubaddressSecretKeyCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.get_subaddress_secret_key(*this);
            }
        };

        struct GetSubaddressRequest: Request {
            cryptonote::subaddress_index index;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(index)
            END_SERIALIZE()
        };
        struct GetSubaddressResponse: Response {
            crypto::public_key C;
            crypto::public_key D;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(C)
                FIELD(D)
            END_SERIALIZE()
        };
        class GetSubaddressCommand: public Command<GetSubaddressRequest, GetSubaddressResponse, 0x5B> {
        public:
            GetSubaddressCommand(): Command() {};
            GetSubaddressCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.get_subaddress(*this);
            }
        };

        struct VerifyKeysRequest: Request {
            crypto::secret_key sec;
            crypto::public_key pub;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(sec)
                FIELD(pub)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) sec.data, sidekick::field_type::KEY);
                return true;
            }
        };
        struct VerifyKeysResponse: Response {
            bool verified;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(verified)
            END_SERIALIZE()
        };
        class VerifyKeysCommand: public Command<VerifyKeysRequest, VerifyKeysResponse, 0x48> {
        public:
            VerifyKeysCommand(): Command() {};
            VerifyKeysCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.verify_keys(*this);
            }
        };

        struct ScalarmultKeyRequest: Request {
            rct::key P;
            rct::key a;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(P)
                FIELD(a)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt(a.bytes, sidekick::field_type::VIEWKEY);
                return true;
            }
        };
        struct ScalarmultKeyResponse: Response {
            rct::key aP;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(aP)
            END_SERIALIZE()
        };
        class ScalarmultKeyCommand: public Command<ScalarmultKeyRequest, ScalarmultKeyResponse, 0x49> {
        public:
            ScalarmultKeyCommand(): Command() {};
            ScalarmultKeyCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.scalarmultKey(*this);
            }
        };

        struct ScalarmultBaseRequest: Request {
            rct::key a;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(a)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt(a.bytes, sidekick::field_type::SCALAR);
                return true;
            }
        };
        struct ScalarmultBaseResponse: Response {
            rct::key aG;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(aG)
            END_SERIALIZE()
        };
        class ScalarmultBaseCommand: public Command<ScalarmultBaseRequest, ScalarmultBaseResponse, 0x4A> {
        public:
            ScalarmultBaseCommand(): Command() {};
            ScalarmultBaseCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.scalarmultBase(*this);
            }
        };

        struct ScSecretAddRequest: Request {
            crypto::secret_key a;
            crypto::secret_key b;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(a)
                FIELD(b)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) a.data, sidekick::field_type::SCALAR);
                device.decrypt((unsigned char*) b.data, sidekick::field_type::SCALAR);
                return true;
            }
        };
        struct ScSecretAddResponse: Response {
            crypto::secret_key rr;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(rr)
            END_SERIALIZE()
            bool encrypt(sidekick &device) {
                device.encrypt((unsigned char*) rr.data, sidekick::field_type::SCALAR);
                return true;
            }
        };
        class ScSecretAddCommand: public Command<ScSecretAddRequest, ScSecretAddResponse, 0x4B> {
        public:
            ScSecretAddCommand(): Command() {};
            ScSecretAddCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.sc_secret_add(*this);
            }
        };

        struct GenerateKeysRequest: Request {
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
            END_SERIALIZE()
        };
        struct GenerateKeysResponse: Response {
            crypto::public_key pub;
            crypto::secret_key sec;
            crypto::secret_key rng;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(pub)
                FIELD(sec)
                FIELD(rng)
            END_SERIALIZE()
            bool encrypt(sidekick &device) {
                device.encrypt((unsigned char*) sec.data, sidekick::field_type::SCALAR);
                device.encrypt((unsigned char*) rng.data, sidekick::field_type::SCALAR);
                return true;
            }
        };
        class GenerateKeysCommand: public Command<GenerateKeysRequest, GenerateKeysResponse, 0x4C> {
        public:
            GenerateKeysCommand(): Command() {};
            GenerateKeysCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.generate_keys(*this);
            }
        };

        struct GenerateKeyDerivationRequest: Request {
            crypto::public_key tx_pub;
            // secret view key is the on the device - no need to transport it
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(tx_pub)
            END_SERIALIZE()
        };
        struct GenerateKeyDerivationResponse: Response {
            crypto::key_derivation derivation;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(derivation)
            END_SERIALIZE()
            bool encrypt(sidekick &device) {
                device.encrypt((unsigned char*) derivation.data, sidekick::field_type::DERIVATION);
                return true;
            }
        };
        class GenerateKeyDerivationCommand: public Command<GenerateKeyDerivationRequest, GenerateKeyDerivationResponse, 0x4D> {
        public:
            GenerateKeyDerivationCommand(): Command() {};
            GenerateKeyDerivationCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.generate_key_derivation(*this);
            }
        };

        struct DerivationToScalarRequest: Request {
            crypto::key_derivation derivation;
            size_t output_index;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(derivation)
                FIELD(output_index)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) derivation.data, sidekick::field_type::DERIVATION);
                return true;
            }
        };
        struct DerivationToScalarResponse: Response {
            crypto::ec_scalar scalar;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(scalar)
            END_SERIALIZE()
            bool encrypt(sidekick &device) {
                device.encrypt((unsigned char*) scalar.data, sidekick::field_type::SCALAR);
                return true;
            }
        };
        class DerivationToScalarCommand: public Command<DerivationToScalarRequest, DerivationToScalarResponse, 0x4E> {
        public:
            DerivationToScalarCommand(): Command() {};
            DerivationToScalarCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.derivation_to_scalar(*this);
            }
        };

        struct DeriveSecretKeyRequest: Request {
            crypto::key_derivation derivation;
            std::size_t output_index;
            crypto::secret_key base;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(derivation)
                FIELD(output_index)
                FIELD(base)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) derivation.data, sidekick::field_type::DERIVATION);
                device.decrypt((unsigned char*) base.data, sidekick::field_type::KEY);
                return true;
            }
        };
        struct DeriveSecretKeyResponse: Response {
            crypto::secret_key derived_key;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(derived_key)
            END_SERIALIZE()
            bool encrypt(sidekick &device) {
                device.encrypt((unsigned char*) derived_key.data, sidekick::field_type::SCALAR);
                return true;
            }
        };
        class DeriveSecretKeyCommand: public Command<DeriveSecretKeyRequest, DeriveSecretKeyResponse, 0x4F> {
        public:
            DeriveSecretKeyCommand(): Command() {};
            DeriveSecretKeyCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.derive_secret_key(*this);
            }
        };

        struct DerivePublicKeyRequest: Request {
            crypto::key_derivation derivation;
            std::size_t output_index;
            crypto::public_key base;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(derivation)
                FIELD(output_index)
                FIELD(base)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) derivation.data, sidekick::field_type::DERIVATION);
                return true;
            }
        };
        struct DerivePublicKeyResponse: Response {
            crypto::public_key derived_key;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(derived_key)
            END_SERIALIZE()
        };
        class DerivePublicKeyCommand: public Command<DerivePublicKeyRequest, DerivePublicKeyResponse, 0x50> {
        public:
            DerivePublicKeyCommand(): Command() {};
            DerivePublicKeyCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.derive_public_key(*this);
            }
        };

        struct SecretToPublicKeyRequest: Request {
            crypto::secret_key sec;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(sec)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) sec.data, sidekick::field_type::SCALAR);
                return true;
            }
        };
        struct SecretToPublicKeyResponse: Response {
            crypto::public_key pubkey;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(pubkey)
            END_SERIALIZE()
        };
        class SecretToPublicKeyCommand: public Command<SecretToPublicKeyRequest, SecretToPublicKeyResponse, 0x51> {
        public:
            SecretToPublicKeyCommand(): Command() {};
            SecretToPublicKeyCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.secret_key_to_public_key(*this);
            }
        };

        struct GenerateKeyImageRequest: Request {
            crypto::public_key pub;
            crypto::secret_key sec;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(pub)
                FIELD(sec)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) sec.data, sidekick::field_type::SCALAR);
                return true;
            }
        };
        struct GenerateKeyImageResponse: Response {
            crypto::key_image image;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(image)
            END_SERIALIZE()
        };
        class GenerateKeyImageCommand: public Command<GenerateKeyImageRequest, GenerateKeyImageResponse, 0x52> {
        public:
            GenerateKeyImageCommand(): Command() {};
            GenerateKeyImageCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.generate_key_image(*this);
            }
        };

        struct DeriveViewTagRequest: Request {
            crypto::key_derivation derivation;
            std::size_t output_index;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(derivation)
                FIELD(output_index)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) derivation.data, sidekick::field_type::DERIVATION);
                return true;
            }
        };
        struct DeriveViewTagResponse: Response {
            crypto::view_tag view_tag;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(view_tag)
            END_SERIALIZE()
        };
        class DeriveViewTagCommand: public Command<DeriveViewTagRequest, DeriveViewTagResponse, 0x62> {
        public:
            DeriveViewTagCommand(): Command() {};
            DeriveViewTagCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.derive_view_tag(*this);
            }
        };

        struct GenerateTxProofRequest: Request {
            crypto::hash prefix_hash;
            crypto::public_key R;
            crypto::public_key A;
            bool has_B;
            crypto::public_key B;
            crypto::public_key D;
            crypto::secret_key rr;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(prefix_hash)
                FIELD(R)
                FIELD(A)
                FIELD(has_B);
                FIELD(B)
                FIELD(D)
                FIELD(rr)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) rr.data, sidekick::field_type::VIEWKEY);
                return true;
            }
        };
        struct GenerateTxProofResponse: Response {
            crypto::signature sig;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(sig)
            END_SERIALIZE()
        };
        class GenerateTxProofCommand: public Command<GenerateTxProofRequest, GenerateTxProofResponse, 0x53> {
        public:
            GenerateTxProofCommand(): Command() {};
            GenerateTxProofCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.generate_tx_proof(*this);
            }
        };

        struct OpenTxRequest: Request {
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
            END_SERIALIZE()
        };
        struct OpenTxResponse: Response {
            crypto::secret_key tx_key;
            crypto::secret_key view_key;
            crypto::secret_key spend_key;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(tx_key)
                FIELD(view_key)
                FIELD(spend_key)
            END_SERIALIZE()
            bool encrypt(sidekick &device) {
                device.encrypt((unsigned char*) tx_key.data, sidekick::field_type::SCALAR);
                device.encrypt((unsigned char*) view_key.data, sidekick::field_type::KEY);
                device.encrypt((unsigned char*) spend_key.data, sidekick::field_type::KEY);
                return true;
            }
        };
        class OpenTxCommand: public Command<OpenTxRequest, OpenTxResponse, 0x54> {
        public:
            OpenTxCommand(): Command() {};
            OpenTxCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.open_tx(*this);
            }
        };

        struct GetTxPrefixHashRequest: Request {
            cryptonote::transaction_prefix tx_prefix;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(tx_prefix)
            END_SERIALIZE()
        };
        struct GetTxPrefixHashResponse: Response {
            crypto::hash h;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(h)
            END_SERIALIZE()
        };
        class GetTxPrefixHashCommand: public Command<GetTxPrefixHashRequest, GetTxPrefixHashResponse, 0x44> {
        public:
            GetTxPrefixHashCommand(): Command() {};
            GetTxPrefixHashCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.get_transaction_prefix_hash(*this);
            }
        };

        struct EncryptPaymentidRequest: Request {
            crypto::hash8 payment_id;
            crypto::public_key public_key;
            crypto::secret_key secret_key;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(payment_id)
                FIELD(public_key)
                FIELD(secret_key)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) secret_key.data, sidekick::field_type::VIEWKEY);
                return true;
            }
        };
        struct EncryptPaymentidResponse: Response {
            crypto::hash8 payment_id;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(payment_id)
            END_SERIALIZE()
        };
        class EncryptPaymentidCommand: public Command<EncryptPaymentidRequest, EncryptPaymentidResponse, 0x56> {
        public:
            EncryptPaymentidCommand(): Command() {};
            EncryptPaymentidCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.encrypt_payment_id(*this);
            }
        };

        struct GenerateOutputEphemeralKeysRequest: Request {
            size_t tx_version;
            crypto::secret_key tx_key;
            crypto::public_key tx_key_pub;
            crypto::public_key Aout;
            crypto::public_key Bout;
            size_t output_index;
            bool is_change;
            bool is_subaddress;
            bool need_additional_tx_key;
            crypto::secret_key additional_tx_key;
            bool use_view_tags;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(tx_version)
                FIELD(tx_key)
                FIELD(tx_key_pub)
                FIELD(Aout)
                FIELD(Bout)
                FIELD(output_index)
                FIELD(is_change)
                FIELD(is_subaddress)
                FIELD(need_additional_tx_key)
                FIELD(additional_tx_key)
                FIELD(use_view_tags)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt((unsigned char*) tx_key.data, sidekick::field_type::VIEWKEY);
                if (need_additional_tx_key)
                    device.decrypt((unsigned char*) additional_tx_key.data, sidekick::field_type::VIEWKEY);
                return true;
            }
        };
        struct GenerateOutputEphemeralKeysResponse: Response {
            crypto::secret_key amount_key;
            crypto::public_key additional_tx_key_pub;
            crypto::public_key out_eph_public_key;
            crypto::view_tag view_tag;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(amount_key)
                FIELD(additional_tx_key_pub)
                FIELD(out_eph_public_key)
                FIELD(view_tag)
            END_SERIALIZE()
            bool encrypt(sidekick &device) {
                device.encrypt((unsigned char*) amount_key.data, sidekick::field_type::AMOUNT_KEY);
                return true;
            }
        };
        class GenerateOutputEphemeralKeysCommand: public Command<GenerateOutputEphemeralKeysRequest, GenerateOutputEphemeralKeysResponse, 0x57> {
        public:
            GenerateOutputEphemeralKeysCommand(): Command() {};
            GenerateOutputEphemeralKeysCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.generate_output_ephemeral_keys(*this);
            }
        };

        struct GenCommitmentMaskRequest: Request {
            rct::key amount_key;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(amount_key)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt(amount_key.bytes, sidekick::field_type::AMOUNT_KEY);
                return true;
            }
        };
        struct GenCommitmentMaskResponse: Response {
            rct::key mask;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(mask)
            END_SERIALIZE()
        };
        class GenCommitmentMaskCommand: public Command<GenCommitmentMaskRequest, GenCommitmentMaskResponse, 0x58> {
        public:
            GenCommitmentMaskCommand(): Command() {};
            GenCommitmentMaskCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.genCommitmentMask(*this);
            }
        };

        struct EdchEncodeRequest: Request {
            rct::ecdhTuple unmasked;
            rct::key sharedSec;
            bool is_short_amount;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(unmasked)
                FIELD(sharedSec)
                FIELD(is_short_amount)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt(sharedSec.bytes, sidekick::field_type::AMOUNT_KEY);
                return true;
            }
        };
        struct EdchEncodeResponse: Response {
            rct::ecdhTuple masked;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(masked)
            END_SERIALIZE()
        };
        class EdchEncodeCommand: public Command<EdchEncodeRequest, EdchEncodeResponse, 0x59> {
        public:
            EdchEncodeCommand(): Command() {};
            EdchEncodeCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.ecdhEncode(*this);
            }
        };

        struct EdchDecodeRequest: Request {
            rct::ecdhTuple masked;
            rct::key sharedSec;
            bool is_short_amount;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(masked)
                FIELD(sharedSec)
                FIELD(is_short_amount)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt(sharedSec.bytes, sidekick::field_type::AMOUNT_KEY);
                return true;
            }
        };
        struct EdchDecodeResponse: Response {
            rct::ecdhTuple unmasked;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(unmasked)
            END_SERIALIZE()
        };
        class EdchDecodeCommand: public Command<EdchDecodeRequest, EdchDecodeResponse, 0x5C> {
        public:
            EdchDecodeCommand(): Command() {};
            EdchDecodeCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.ecdhDecode(*this);
            }
        };

        struct ClsagPrepareRequest: Request {
            rct::key p;
            rct::key z;
            rct::key H;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(p)
                FIELD(z)
                FIELD(H)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt(p.bytes, sidekick::field_type::SCALAR);
                return true;
            }
        };
        struct ClsagPrepareResponse: Response {
            rct::key I;
            rct::key D;
            rct::key a;
            rct::key aG;
            rct::key aH;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(I)
                FIELD(D)
                FIELD(a)
                FIELD(aG)
                FIELD(aH)
            END_SERIALIZE()
            bool encrypt(sidekick &device) {
                device.encrypt(a.bytes, sidekick::field_type::ALPHA);
                return true;
            }
        };
        class ClsagPrepareCommand: public Command<ClsagPrepareRequest, ClsagPrepareResponse, 0x5D> {
        public:
            ClsagPrepareCommand(): Command() {};
            ClsagPrepareCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.clsag_prepare(*this);
            }
        };

        struct ClsagHashRequest: Request {
            rct::keyV data;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(data)
            END_SERIALIZE()
        };
        struct ClsagHashResponse: Response {
            rct::key hash;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(hash)
            END_SERIALIZE()
        };
        class ClsagHashCommand: public Command<ClsagHashRequest, ClsagHashResponse, 0x5E> {
        public:
            ClsagHashCommand(): Command() {};
            ClsagHashCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.clsag_hash(*this);
            }
        };

        struct ClsagSignRequest: Request {
            rct::key a;
            rct::key p;
            rct::key z;
            rct::key mu_P;
            rct::key mu_C;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(a)
                FIELD(p)
                FIELD(z)
                FIELD(mu_P)
                FIELD(mu_C)
            END_SERIALIZE()
            bool decrypt(const sidekick &device) {
                device.decrypt(a.bytes, sidekick::field_type::ALPHA);
                device.decrypt(p.bytes, sidekick::field_type::SCALAR);
                return true;
            }
        };
        struct ClsagSignResponse: Response {
            rct::key s;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(s)
            END_SERIALIZE()
        };
        class ClsagSignCommand: public Command<ClsagSignRequest, ClsagSignResponse, 0x5F> {
        public:
            ClsagSignCommand(): Command() {};
            ClsagSignCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.clsag_sign(*this);
            }
        };

        struct CloseTxRequest: Request {
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
            END_SERIALIZE()
        };
        struct CloseTxResponse: Response {
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
            END_SERIALIZE()
        };
        class CloseTxCommand: public Command<CloseTxRequest, CloseTxResponse, 0x55> {
        public:
            CloseTxCommand(): Command() {};
            CloseTxCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.close_tx(*this);
            }
        };

        struct ResetRequest: Request {
            unsigned int version;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(version)
            END_SERIALIZE()
        };
        struct ResetResponse: Response {
            unsigned int version;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(version)
            END_SERIALIZE()
        };
        class ResetCommand: public Command<ResetRequest, ResetResponse, 0x5A> {
        public:
            ResetCommand(): Command() {};
            ResetCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.reset(*this);
            }
        };

        struct PrehashRequest: Request {
            std::string blob;
            size_t inputs_size;
            size_t outputs_size;
            rct::keyV hashes;
            rct::ctkeyV outPk;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(blob)
                FIELD(inputs_size)
                FIELD(outputs_size)
                FIELD(hashes)
                FIELD(outPk)
            END_SERIALIZE()
        };
        struct PrehashResponse: Response {
            rct::key prehash;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(prehash)
            END_SERIALIZE()
        };
        class PrehashCommand: public Command<PrehashRequest, PrehashResponse, 0x60> {
        public:
            PrehashCommand(): Command() {};
            PrehashCommand(const std::string &requestData, const sidekick &device): Command(requestData, device) {}
            void execute(sidekick &device) {
                res.rc = device.prehash(*this);
            }
        };
    }
}
