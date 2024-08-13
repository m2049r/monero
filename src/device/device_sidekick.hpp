// Copyright (c) 2017-2020, The Monero Project
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
#ifdef HAVE_MONERUJO
#include "device_io_monerujo_bt.hpp"
#endif

namespace hw {
    namespace sidekick {

        void register_all(std::map<std::string, std::unique_ptr<device>> &registry);

        const unsigned char FAKE_SECRET_VIEW_KEY[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        const unsigned char FAKE_SECRET_SPEND_KEY[32] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        /* Minimal supported device version */
        #define MIN_APP_VERSION_MAJOR    0
        #define MIN_APP_VERSION_MINOR    1
        #define MIN_APP_VERSION_MICRO    0

        #define VERSION(M,m,u) ((M)<<24|(m)<<16|(u)<<8)
        #define VERSION_MAJOR(v)       (((v)>>24)&0xFF)
        #define VERSION_MINOR(v)       (((v)>>16)&0xFF)
        #define VERSION_MICRO(v)       (((v)>>8)&0xFF)

        #define MIN_APP_VERSION VERSION(MIN_APP_VERSION_MAJOR, MIN_APP_VERSION_MINOR, MIN_APP_VERSION_MICRO)

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

        class device_sidekick : public hw::device {
        private:
            unsigned int  id;
            // Locker for concurrent access
            mutable boost::recursive_mutex device_locker;
            mutable boost::mutex command_locker;

            //IO
            hw::io::device_io_monerujo_bt hw_device;
            unsigned char buffer[4096];

            // To speed up blockchain parsing the view key maybe handle here.
            crypto::secret_key viewkey;
            bool has_view_key;

            static device_sidekick* instance;
        public:
            static device_sidekick* Instance();
            device_sidekick();
            ~device_sidekick();

            device_sidekick(const device_sidekick &device) = delete;
            device_sidekick& operator=(const device_sidekick &device) = delete;

            explicit operator bool() const override { return false; };

            std::string exchange(const std::string out);

            bool  reset(void);

            /* ======================================================================= */
            /*                              SETUP/TEARDOWN                             */
            /* ======================================================================= */
            bool set_name(const std::string &name) override;
            const std::string get_name() const override;

            bool init(void) override;
            bool release() override;

            bool connected(void) const;
            bool connect(void) override;
            bool disconnect() override;

            bool set_mode(device_mode mode) override;

            device_type get_type() const override {return device_type::SIDEKICK;};

            /* ======================================================================= */
            /*  LOCKER                                                                 */
            /* ======================================================================= */
            void lock(void)  override;
            void unlock(void) override;
            bool try_lock(void) override;

            /* ======================================================================= */
            /*                             WALLET & ADDRESS                            */
            /* ======================================================================= */
            bool  get_public_address(cryptonote::account_public_address &pubkey) override;
            bool  get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey) override;
            bool  generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key, uint64_t kdf_rounds) override;
            void  display_address(const cryptonote::subaddress_index& index, const boost::optional<crypto::hash8> &payment_id) override;

            /* ======================================================================= */
            /*                               SUB ADDRESS                               */
            /* ======================================================================= */
            bool  derive_subaddress_public_key(const crypto::public_key &pub, const crypto::key_derivation &derivation, const std::size_t output_index,  crypto::public_key &derived_pub) override;
            crypto::public_key  get_subaddress_spend_public_key(const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index) override;
            std::vector<crypto::public_key>  get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end) override;
            cryptonote::account_public_address  get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) override;
            crypto::secret_key  get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index) override;

            /* ======================================================================= */
            /*                            DERIVATION & KEY                             */
            /* ======================================================================= */
            bool  verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key)  override;
            bool  scalarmultKey(rct::key & aP, const rct::key &P, const rct::key &a) override;
            bool  scalarmultBase(rct::key &aG, const rct::key &a) override;
            bool  sc_secret_add(crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b) override;
            crypto::secret_key  generate_keys(crypto::public_key &pub, crypto::secret_key &sec, const crypto::secret_key& recovery_key = crypto::secret_key(), bool recover = false) override;
            bool  generate_key_derivation(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation) override;
            bool  conceal_derivation(crypto::key_derivation &derivation, const crypto::public_key &tx_pub_key, const std::vector<crypto::public_key> &additional_tx_pub_keys, const crypto::key_derivation &main_derivation, const std::vector<crypto::key_derivation> &additional_derivations) override;
            bool  derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res) override;
            bool  derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &sec,  crypto::secret_key &derived_sec) override;
            bool  derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &pub,  crypto::public_key &derived_pub) override;
            bool  secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) override;
            bool  generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image) override;
            bool  derive_view_tag(const crypto::key_derivation &derivation, const std::size_t output_index, crypto::view_tag &view_tag) override;


            /* ======================================================================= */
            /*                               TRANSACTION                               */
            /* ======================================================================= */

            void generate_tx_proof(const crypto::hash &prefix_hash,
                                   const crypto::public_key &R, const crypto::public_key &A, const boost::optional<crypto::public_key> &B, const crypto::public_key &D, const crypto::secret_key &r,
                                   crypto::signature &sig) override;

            bool  open_tx(crypto::secret_key &tx_key) override;
            void get_transaction_prefix_hash(const cryptonote::transaction_prefix& tx, crypto::hash& h) override;

            bool  encrypt_payment_id(crypto::hash8 &payment_id, const crypto::public_key &public_key, const crypto::secret_key &secret_key) override;

            rct::key genCommitmentMask(const rct::key &amount_key) override;

            bool  ecdhEncode(rct::ecdhTuple & unmasked, const rct::key & sharedSec, bool short_amount) override;
            bool  ecdhDecode(rct::ecdhTuple & masked, const rct::key & sharedSec, bool short_amount) override;

            bool  generate_output_ephemeral_keys(const size_t tx_version, const cryptonote::account_keys &sender_account_keys, const crypto::public_key &txkey_pub,  const crypto::secret_key &tx_key,
                                                 const cryptonote::tx_destination_entry &dst_entr, const boost::optional<cryptonote::account_public_address> &change_addr, const size_t output_index,
                                                 const bool &need_additional_txkeys, const std::vector<crypto::secret_key> &additional_tx_keys,
                                                 std::vector<crypto::public_key> &additional_tx_public_keys,
                                                 std::vector<rct::key> &amount_keys,
                                                 crypto::public_key &out_eph_public_key,
                                                 const bool use_view_tags, crypto::view_tag &view_tag) override;

            bool  mlsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size, const rct::keyV &hashes, const rct::ctkeyV &outPk, rct::key &prehash) override;

            // only CLSAG supported
            bool  mlsag_prepare(const rct::key &H, const rct::key &xx, rct::key &a, rct::key &aG, rct::key &aHP, rct::key &rvII) override {dfns();};
            bool  mlsag_prepare(rct::key &a, rct::key &aG) override {dfns();};
            bool  mlsag_hash(const rct::keyV &long_message, rct::key &c) override {dfns();};
            bool  mlsag_sign(const rct::key &c, const rct::keyV &xx, const rct::keyV &alpha, const size_t rows, const size_t dsRows, rct::keyV &ss) override {dfns();};

            bool clsag_prepare(const rct::key &p, const rct::key &z, rct::key &I, rct::key &D, const rct::key &H, rct::key &a, rct::key &aG, rct::key &aH) override;
            bool clsag_hash(const rct::keyV &data, rct::key &hash) override;
            bool clsag_sign(const rct::key &c, const rct::key &a, const rct::key &p, const rct::key &z, const rct::key &mu_P, const rct::key &mu_C, rct::key &s) override;

            bool  close_tx(void) override;
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
        };
        struct Response {
            Response() = default;
            int rc = RC_UNDEF;
            int correlationId;
            BEGIN_SERIALIZE_OBJECT()
                FIELD(rc)
                FIELD(correlationId)
            END_SERIALIZE()
        };
        template <class RequestType, class ResponseType, int CID>
        class Command {
        public:
            enum {ID=CID};
            RequestType req;
            ResponseType res;
            Command() {req.commandId = CID;} // TODO: generate correlationId & set it
            Command(const std::string &requestData) {
                res.correlationId = req.correlationId;
            }

            std::string serializeRequest() { // should be const but can't because auf do_serialize impl
                std::stringstream ss;
                binary_archive<true> ba(ss);
                CHECK_AND_ASSERT_THROW_MES(do_serialize(ba, req), "failed to serialize request");
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

            // monero-side
            void call() {
                // serialize the request
                LOG_PRINT_L3("call");
                std::string request = serializeRequest();
                LOG_PRINT_L3("REQ " << std::hex << ID);

                // send the request, get the response
                std::string response = device_sidekick::Instance()->exchange(request);

                char logstr[4096];
                buffer_to_str(logstr, sizeof(logstr),  response.c_str(), response.size());
                LOG_PRINT_L3("RES len=" << response.size() << ": " << logstr);

                CHECK_AND_ASSERT_THROW_MES(checkResponse(response), "computer says no");
                // blocking call - timeout? mark user input required
                // deserialize the reply
                if (!deserializeResponse(response))
                    ASSERT_MES_AND_THROW("invalid data");
                LOG_PRINT_L3("RC=" << std::hex << res.rc);
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
            SetSigModeCommand(const std::string &requestData): Command(requestData) {}
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
            GenerateChachaKeyCommand(const std::string &requestData): Command(requestData) {}
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
            GetPublicKeysCommand(const std::string &requestData): Command(requestData) {}
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
        };
        class GetSecretKeysCommand: public Command<GetSecretKeysRequest, GetSecretKeysResponse, 0x43> {
        public:
            GetSecretKeysCommand(): Command() {};
            GetSecretKeysCommand(const std::string &requestData): Command(requestData) {}
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
            DisplayAddressCommand(const std::string &requestData): Command(requestData) {}
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
            DeriveSubaddressPublicKeyCommand(const std::string &requestData): Command(requestData) {}
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
            GetSubaddressSpendPublicKeyCommand(const std::string &requestData): Command(requestData) {}
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
        };
        class GetSubaddressSecretKeyCommand: public Command<GetSubaddressSecretKeyRequest, GetSubaddressSecretKeyResponse, 0x47> {
        public:
            GetSubaddressSecretKeyCommand(): Command() {};
            GetSubaddressSecretKeyCommand(const std::string &requestData): Command(requestData) {}
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
            GetSubaddressCommand(const std::string &requestData): Command(requestData) {}
        };

        struct VerifyKeysRequest: Request {
            crypto::secret_key sec;
            crypto::public_key pub;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(sec)
                FIELD(pub)
            END_SERIALIZE()
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
            VerifyKeysCommand(const std::string &requestData): Command(requestData) {}
        };

        struct ScalarmultKeyRequest: Request {
            rct::key P;
            rct::key a;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(P)
                FIELD(a)
            END_SERIALIZE()
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
            ScalarmultKeyCommand(const std::string &requestData): Command(requestData) {}
        };

        struct ScalarmultBaseRequest: Request {
            rct::key a;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(a)
            END_SERIALIZE()
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
            ScalarmultBaseCommand(const std::string &requestData): Command(requestData) {}
        };

        struct ScSecretAddRequest: Request {
            crypto::secret_key a;
            crypto::secret_key b;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(a)
                FIELD(b)
            END_SERIALIZE()
        };
        struct ScSecretAddResponse: Response {
            crypto::secret_key rr;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(rr)
            END_SERIALIZE()
        };
        class ScSecretAddCommand: public Command<ScSecretAddRequest, ScSecretAddResponse, 0x4B> {
        public:
            ScSecretAddCommand(): Command() {};
            ScSecretAddCommand(const std::string &requestData): Command(requestData) {}
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
        };
        class GenerateKeysCommand: public Command<GenerateKeysRequest, GenerateKeysResponse, 0x4C> {
        public:
            GenerateKeysCommand(): Command() {};
            GenerateKeysCommand(const std::string &requestData): Command(requestData) {}
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
        };
        class GenerateKeyDerivationCommand: public Command<GenerateKeyDerivationRequest, GenerateKeyDerivationResponse, 0x4D> {
        public:
            GenerateKeyDerivationCommand(): Command() {};
            GenerateKeyDerivationCommand(const std::string &requestData): Command(requestData) {}
        };

        struct DerivationToScalarRequest: Request {
            crypto::key_derivation derivation;
            size_t output_index;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(derivation)
                FIELD(output_index)
            END_SERIALIZE()
        };
        struct DerivationToScalarResponse: Response {
            crypto::ec_scalar scalar;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(scalar)
            END_SERIALIZE()
        };
        class DerivationToScalarCommand: public Command<DerivationToScalarRequest, DerivationToScalarResponse, 0x4E> {
        public:
            DerivationToScalarCommand(): Command() {};
            DerivationToScalarCommand(const std::string &requestData): Command(requestData) {}
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
        };
        struct DeriveSecretKeyResponse: Response {
            crypto::secret_key derived_key;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Response&)*this)
                FIELD(derived_key)
            END_SERIALIZE()
        };
        class DeriveSecretKeyCommand: public Command<DeriveSecretKeyRequest, DeriveSecretKeyResponse, 0x4F> {
        public:
            DeriveSecretKeyCommand(): Command() {};
            DeriveSecretKeyCommand(const std::string &requestData): Command(requestData) {}
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
            DerivePublicKeyCommand(const std::string &requestData): Command(requestData) {}
        };

        struct SecretToPublicKeyRequest: Request {
            crypto::secret_key sec;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(sec)
            END_SERIALIZE()
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
            SecretToPublicKeyCommand(const std::string &requestData): Command(requestData) {}
        };

        struct GenerateKeyImageRequest: Request {
            crypto::public_key pub;
            crypto::secret_key sec;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(pub)
                FIELD(sec)
            END_SERIALIZE()
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
            GenerateKeyImageCommand(const std::string &requestData): Command(requestData) {}
        };

        struct DeriveViewTagRequest: Request {
            crypto::key_derivation derivation;
            std::size_t output_index;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(derivation)
                FIELD(output_index)
            END_SERIALIZE()
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
            DeriveViewTagCommand(const std::string &requestData): Command(requestData) {}
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
            GenerateTxProofCommand(const std::string &requestData): Command(requestData) {}
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
        };
        class OpenTxCommand: public Command<OpenTxRequest, OpenTxResponse, 0x54> {
        public:
            OpenTxCommand(): Command() {};
            OpenTxCommand(const std::string &requestData): Command(requestData) {}
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
            GetTxPrefixHashCommand(const std::string &requestData): Command(requestData) {}
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
            EncryptPaymentidCommand(const std::string &requestData): Command(requestData) {}
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
        };
        class GenerateOutputEphemeralKeysCommand: public Command<GenerateOutputEphemeralKeysRequest, GenerateOutputEphemeralKeysResponse, 0x57> {
        public:
            GenerateOutputEphemeralKeysCommand(): Command() {};
            GenerateOutputEphemeralKeysCommand(const std::string &requestData): Command(requestData) {}
        };

        struct GenCommitmentMaskRequest: Request {
            rct::key amount_key;
            BEGIN_SERIALIZE_OBJECT()
                FIELDS((Request&)*this)
                FIELD(amount_key)
            END_SERIALIZE()
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
            GenCommitmentMaskCommand(const std::string &requestData): Command(requestData) {}
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
            EdchEncodeCommand(const std::string &requestData): Command(requestData) {}
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
            EdchDecodeCommand(const std::string &requestData): Command(requestData) {}
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
        };
        class ClsagPrepareCommand: public Command<ClsagPrepareRequest, ClsagPrepareResponse, 0x5D> {
        public:
            ClsagPrepareCommand(): Command() {};
            ClsagPrepareCommand(const std::string &requestData): Command(requestData) {}
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
            ClsagHashCommand(const std::string &requestData): Command(requestData) {}
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
            ClsagSignCommand(const std::string &requestData): Command(requestData) {}
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
            CloseTxCommand(const std::string &requestData): Command(requestData) {}
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
            ResetCommand(const std::string &requestData): Command(requestData) {}
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
            PrehashCommand(const std::string &requestData): Command(requestData) {}
        };
    }
}
