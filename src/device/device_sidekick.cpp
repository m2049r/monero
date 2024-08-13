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

namespace hw {
    namespace sidekick {

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

        device_sidekick::device_sidekick() {
            this->id = device_id++;
            this->mode = NONE;
            this->has_view_key = false;
            MDEBUG("Device " << this->id <<" created");
        }

        device_sidekick::~device_sidekick() {
            this->release();
            MDEBUG("Device " <<this->id <<" destroyed");
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
        bool device_sidekick::reset() {
            LOG_PRINT_L3(">>reset");
            ResetCommand cmd;
            cmd.req.version = monero_version();
            // if (v == 0) throw something
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            uint32_t &v = cmd.res.version; // device version
            CHECK_AND_ASSERT_THROW_MES(v >= MIN_APP_VERSION,
                        "Unsupported device version: "
                        << VERSION_MAJOR(v)<<"."<<VERSION_MINOR(v)<<"."<<VERSION_MICRO(v)
                        << " Minimum is " << MIN_APP_VERSION_MAJOR<<"."<<MIN_APP_VERSION_MINOR<<"."<<MIN_APP_VERSION_MICRO);
            LOG_PRINT_L3("<<reset");
            return true;
        }
        // exchange with sidekick
        std::string device_sidekick::exchange(const std::string out) {
            unsigned int len = hw_device.exchange((unsigned char*) out.c_str(), out.size(), this->buffer, sizeof(this->buffer), false);
            CHECK_AND_ASSERT_THROW_MES(len >= 0, "error in echange");
            return std::string((char*) buffer, len);
        }

        /* ======================================================================= */
        /*                              SETUP/TEARDOWN                             */
        /* ======================================================================= */

        bool device_sidekick::set_name(const std::string &name)  {
            this->name = name;
            return true;
        }
        const std::string device_sidekick::get_name()  const {
            if (!this->connected()) {
                return std::string("<disconnected:").append(this->name).append(">");
            }
        return this->name;
        }

        bool device_sidekick::init(void) {
            this->release();
            hw_device.init();
            return true;
        }
        bool device_sidekick::release() {
            this->disconnect();
            hw_device.release();
            return true;
        }

        bool device_sidekick::connected(void) const {
            return hw_device.connected();
        }

        bool device_sidekick::connect(void) {
            this->disconnect();
            this->reset();
            crypto::secret_key vkey;
            crypto::secret_key skey;
            this->get_secret_keys(vkey,skey);
            return true;
        }

        bool device_sidekick::disconnect() {
            hw_device.disconnect();
            return true;
        }

        bool device_sidekick::set_mode(device_mode mode) {
            LOG_PRINT_L3(">>set_mode " << mode);
            switch(mode) {
            case TRANSACTION_CREATE_REAL:
            case TRANSACTION_CREATE_FAKE:
            {
                SetSigModeCommand cmd;
                cmd.req.sig_mode = mode;
                cmd.call();
                CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
                CHECK_AND_ASSERT_THROW_MES(cmd.res.sig_mode == mode, "mode was not set on device");
                break;
            }
            case TRANSACTION_PARSE: 
            case NONE:
                break;
            default:
                CHECK_AND_ASSERT_THROW_MES(false, " invalid mode: " << mode);
            }
            device::set_mode( mode);
            LOG_PRINT_L3("<<set_mode");
            return true;
        }

        /* ======================================================================= */
        /*  LOCKER                                                                 */
        /* ======================================================================= */ 
        
        //automatic lock one more level on device ensuring the current thread is allowed to use it
        #define AUTO_LOCK_CMD() \
        /* lock both mutexes without deadlock*/ \
        boost::lock(device_locker, command_locker); \
        /* make sure both already-locked mutexes are unlocked at the end of scope */ \
        boost::lock_guard<boost::recursive_mutex> lock1(device_locker, boost::adopt_lock); \
        boost::lock_guard<boost::mutex> lock2(command_locker, boost::adopt_lock)

        // lock the device for a long sequence
        void device_sidekick::lock(void) {
            LOG_PRINT_L3("LOCKING " << this->name);
            device_locker.lock();
            LOG_PRINT_L3("LOCKED  " << this->name);
        }

        // lock the device for a long sequence
        bool device_sidekick::try_lock(void) {
            LOG_PRINT_L3("LOCKING(try) " << this->name);
            bool r = device_locker.try_lock();
            if (r) {
                LOG_PRINT_L3("LOCKed(try)  " << this->name);
            } else {
                LOG_PRINT_L3("!LOCKed(try) " << this->name);
            }
            return r;
        }

        // lock the device for a long sequence
        void device_sidekick::unlock(void) {
            LOG_PRINT_L3("UNLOCKING " << this->name);
            device_locker.unlock();
            LOG_PRINT_L3("UNLOCKed  " << this->name);
        }

        /* ======================================================================= */
        /*                             WALLET & ADDRESS                            */
        /* ======================================================================= */

        // keys are ignored - we use our own on the device
        bool device_sidekick::generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key, uint64_t kdf_rounds) {
            LOG_PRINT_L3(">>generate_chacha_key " <<keys.m_view_secret_key<<keys.m_spend_secret_key<<" "<<kdf_rounds);
            // CALL (kdf_rounds) => key            
            GenerateChachaKeyCommand cmd;
            cmd.req.kdf_rounds = kdf_rounds;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            key = cmd.res.key;
            LOG_PRINT_L3("<<generate_chacha_key " << key);
            return true;
        }

        bool device_sidekick::get_public_address(cryptonote::account_public_address &pubkey) {
            LOG_PRINT_L3(">>get_public_address");
            // CALL ()
            GetPublicKeysCommand cmd;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            pubkey = cmd.res.pubkey;
            LOG_PRINT_L3("<<get_public_address " <<pubkey.m_view_public_key<< pubkey.m_spend_public_key);
            return true;
        }

        bool device_sidekick::get_secret_keys(crypto::secret_key &a , crypto::secret_key &b)  {
            LOG_PRINT_L3(">>get_secret_keys");
            GetSecretKeysCommand cmd;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            a = cmd.res.viewkey;
            b = cmd.res.spendkey;
            this->viewkey = a;
            this->has_view_key = !is_fake_view_key(this->viewkey);
            LOG_PRINT_L3("<<get_secret_keys " <<a<<b<< this->has_view_key);
            return true;
        }

        void device_sidekick::display_address(const cryptonote::subaddress_index& index, const boost::optional<crypto::hash8> &payment_id) {
            LOG_PRINT_L3(">>display_address");
            if (payment_id)
                LOG_PRINT_L3(">>display_address: payment_id=" << payment_id.value());
            // CALL (index, payment_id) - displays address on device
            DisplayAddressCommand cmd;
            cmd.req.index = index;
            if (payment_id)
                cmd.req.payment_id = payment_id.value();
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            //TODO: what if this goes wrong? (can this go wrong?)
            LOG_PRINT_L3("<<display_address");
        }

        /* ======================================================================= */
        /*                               SUB ADDRESS                               */
        /* ======================================================================= */

        bool device_sidekick::derive_subaddress_public_key(const crypto::public_key &out_key, const crypto::key_derivation &derivation, const std::size_t output_index, crypto::public_key &derived_key) {
            LOG_PRINT_L3(">>derive_subaddress_public_key p,d,i " << out_key << derivation << " " << output_index);
            if ((this->mode == TRANSACTION_PARSE) && has_view_key) {
                //If we are in TRANSACTION_PARSE, the given derivation has been retrieved uncrypted (wihtout the help
                //of the device), so continue that way.
                bool r = crypto::derive_subaddress_public_key(out_key, derivation, output_index, derived_key);
                LOG_PRINT_L3("<<derive_subaddress_public_key (PARSE) " << derived_key);
                return r;
            } else {
                // CALL (pub, derivation/S, output_index)
                DeriveSubaddressPublicKeyCommand cmd;
                cmd.req.out_key = out_key;
                cmd.req.derivation = derivation;
                cmd.req.output_index = output_index;
                cmd.call();
                CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
                derived_key = cmd.res.derived_key;
                LOG_PRINT_L3("<<derive_subaddress_public_key " << derived_key);
                return true;
            }
        }

        // keys are ignored - we either know the main address or calculate it with our won keys
        crypto::public_key device_sidekick::get_subaddress_spend_public_key(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) {
            LOG_PRINT_L3(">>get_subaddress_spend_public_key " << keys.m_view_secret_key<<keys.m_spend_secret_key <<" "<<index);
            if (index.is_zero()) {
                LOG_PRINT_L3("<<get_subaddress_spend_public_key ZERO " << keys.m_account_address.m_spend_public_key);
                return keys.m_account_address.m_spend_public_key;
            }
            // CALL (index)
            GetSubaddressSpendPublicKeyCommand cmd;
            cmd.req.index = index;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            LOG_PRINT_L3("<<get_subaddress_spend_public_key " << cmd.res.D);
            return cmd.res.D;
        }

        std::vector<crypto::public_key> device_sidekick::get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end) {
            LOG_PRINT_L3(">>get_subaddress_spend_public_keys");
            CHECK_AND_ASSERT_THROW_MES(begin <= end, "begin > end");

            std::vector<crypto::public_key> pkeys;
            for (cryptonote::subaddress_index index = {account, begin}; index.minor < end; ++index.minor) {
                crypto::public_key D = this->get_subaddress_spend_public_key(keys, index);
                pkeys.push_back(D);
                LOG_PRINT_L3("<<get_subaddress_spend_public_key " << D);
            }
            LOG_PRINT_L3("<<get_subaddress_spend_public_keys");
            return pkeys;
        }

        // keys are ignored
        cryptonote::account_public_address device_sidekick::get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) {
            LOG_PRINT_L3(">>get_subaddress " << keys.m_view_secret_key<<keys.m_spend_secret_key <<" "<<index);
            if (index.is_zero())
                return keys.m_account_address;
            GetSubaddressCommand cmd;
            cmd.req.index = index;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            LOG_PRINT_L3("<<get_subaddress " << cmd.res.C  << cmd.res.D);
            cryptonote::account_public_address address;
            address.m_view_public_key = cmd.res.C;
            address.m_spend_public_key = cmd.res.D;
            return address;
        }

        // ignore sec as we have it (secret view key) on the device
        crypto::secret_key device_sidekick::get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index) {
            LOG_PRINT_L3(">>get_subaddress_secret_key " <<sec <<" "<<index);
            // CALL/S (sec/S, index)
            GetSubaddressSecretKeyCommand cmd;
            cmd.req.index = index;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            LOG_PRINT_L3("<<get_subaddress_secret_key " << cmd.res.m);
            return cmd.res.m;
        }

        /* ======================================================================= */
        /*                            DERIVATION & KEY                             */
        /* ======================================================================= */

        bool device_sidekick::verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) {
            LOG_PRINT_L3(">>verify_keys " << secret_key << public_key);
            // verify spend_secret => spend_public or view_secret => view_public
            // CALL (secret_key/S, public_key)
            VerifyKeysCommand cmd;
            cmd.req.sec = secret_key;
            cmd.req.pub = public_key;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            LOG_PRINT_L3("<<verify_keys ==" << cmd.res.verified);
            return cmd.res.verified;
        }

        bool device_sidekick::scalarmultKey(rct::key & aP, const rct::key &P, const rct::key &a) {
            LOG_PRINT_L3(">>scalarmultKey " <<a<<P);
            // CALL (P, a/S)
            ScalarmultKeyCommand cmd;
            cmd.req.a = a;
            cmd.req.P = P;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            aP = cmd.res.aP;
            LOG_PRINT_L3("<<scalarmultKey " <<aP);
            return true;
        }

        bool device_sidekick::scalarmultBase(rct::key &aG, const rct::key &a) {
            LOG_PRINT_L3(">>scalarmultBase " <<a);
            // CALL (a/S)
            ScalarmultBaseCommand cmd;
            cmd.req.a = a;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            aG = cmd.res.aG;
            LOG_PRINT_L3("<<scalarmultBase " <<aG);
            return true;
        }

        bool device_sidekick::sc_secret_add(crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b) {
            LOG_PRINT_L3(">>sc_secret_add " <<a<<b);
            // CALL/S (a/S, b/S)
            ScSecretAddCommand cmd;
            cmd.req.a = a;
            cmd.req.b = b;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            r = cmd.res.rr;
            LOG_PRINT_L3("<<sc_secret_add " <<r);
            return true;
        }

        crypto::secret_key device_sidekick::generate_keys(crypto::public_key &pub, crypto::secret_key &sec, const crypto::secret_key& recovery_key, bool recover) {
            LOG_PRINT_L3(">>generate_keys");
            CHECK_AND_ASSERT_THROW_MES(!recover,"device generate key does not support recover");
            // CALL () => pub, sec/S
            GenerateKeysCommand cmd;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            pub = cmd.res.pub;
            sec = cmd.res.sec;
            LOG_PRINT_L3("<<generate_keys " << pub<<sec<<cmd.res.rng);
            return cmd.res.rng;
        }

        // sec_view is ignored as we have it or the device has it
        bool device_sidekick::generate_key_derivation(const crypto::public_key &tx_pub, const crypto::secret_key &sec_view, crypto::key_derivation &derivation) {
            LOG_PRINT_L3(">>generate_key_derivation " << tx_pub << sec_view);
            if ((this->mode == TRANSACTION_PARSE)  && this->has_view_key) {
                //A derivation is resquested in PASRE mode and we have the view key,
                //so do that without the device and return the derivation unencrypted.
                bool r = crypto::wallet::generate_key_derivation(tx_pub, this->viewkey, derivation);
                LOG_PRINT_L3("<<generate_key_derivation (PARSE) " << derivation);
                return r;
            } else {
                // CALL/S (pub, sec/S)
                GenerateKeyDerivationCommand cmd;
                cmd.req.tx_pub = tx_pub;
                cmd.call();
                CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
                derivation = cmd.res.derivation;
                LOG_PRINT_L3("<<generate_key_derivation " << derivation);
                return true;
            }
        }

        bool device_sidekick::conceal_derivation(crypto::key_derivation &derivation, const crypto::public_key &tx_pub_key, const std::vector<crypto::public_key> &additional_tx_pub_keys, const crypto::key_derivation &main_derivation, const std::vector<crypto::key_derivation> &additional_derivations) {
            LOG_PRINT_L3(">>conceal_derivation " << tx_pub_key);
            const crypto::public_key *pkey = NULL;
            if (derivation == main_derivation) {        
                pkey = &tx_pub_key;
                LOG_PRINT_L3("conceal derivation with main tx pub key");
            } else {
                for (size_t n = 0; n < additional_derivations.size(); ++n) {
                    if (derivation == additional_derivations[n]) {
                        pkey = &additional_tx_pub_keys[n];
                        LOG_PRINT_L3("conceal derivation with additional tx pub key");
                        break;
                    }
                }
            }
            CHECK_AND_ASSERT_THROW_MES(pkey, "Mismatched derivation on scan info");
            LOG_PRINT_L3("<<conceal_derivation " << *pkey);
            return this->generate_key_derivation(*pkey, crypto::null_skey, derivation);
        }

        bool device_sidekick::derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res) {
            LOG_PRINT_L3(">>derivation_to_scalar " << derivation <<" "<<output_index);
            // CALL/S (derivation/S, output_index)
            DerivationToScalarCommand cmd;
            cmd.req.derivation = derivation;
            cmd.req.output_index = output_index;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            res = cmd.res.scalar;
            LOG_PRINT_L3("<<derivation_to_scalar " <<res);
            return true;
        }

        bool device_sidekick::derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &base, crypto::secret_key &derived_key){
            LOG_PRINT_L3(">>derive_secret_key " << derivation<<" "<<output_index<<base);
            // CALL/S (derivation/S, output_index, base/S)
            DeriveSecretKeyCommand cmd;
            cmd.req.derivation = derivation;
            cmd.req.output_index = output_index;
            cmd.req.base = base;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            derived_key = cmd.res.derived_key;
            LOG_PRINT_L3("<<derive_secret_key " << derived_key);
            return true;
        }

        bool device_sidekick::derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &base, crypto::public_key &derived_key) {
            LOG_PRINT_L3(">>derive_public_key " <<derivation<<" "<<output_index<<base);
            // CALL (derivation/S, output_index, base)
            DerivePublicKeyCommand cmd;
            cmd.req.derivation = derivation;
            cmd.req.output_index = output_index;
            cmd.req.base = base;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            derived_key = cmd.res.derived_key;
            LOG_PRINT_L3("<<derive_public_key " <<derived_key);
            return true;
        }

        bool device_sidekick::secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) {
            LOG_PRINT_L3(">>secret_key_to_public_key " <<sec);
            // CALL (secret_key/S)
            SecretToPublicKeyCommand cmd;
            cmd.req.sec = sec;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            pub = cmd.res.pubkey;
            LOG_PRINT_L3("<<secret_key_to_public_key " <<pub);
            return true;
        }

        bool device_sidekick::generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image) {
            LOG_PRINT_L3(">>generate_key_image " <<pub<<sec);
            // CALL (pub, sec/S)
            GenerateKeyImageCommand cmd;
            cmd.req.pub = pub;
            cmd.req.sec = sec;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            image = cmd.res.image;
            LOG_PRINT_L3("<<generate_key_image " <<image);
            return true;
        }

        bool device_sidekick::derive_view_tag(const crypto::key_derivation &derivation, const std::size_t output_index, crypto::view_tag &view_tag) {
            LOG_PRINT_L3(">>derive_view_tag " <<derivation <<"/"<< output_index);
            if ((this->mode == TRANSACTION_PARSE) && has_view_key) {
                //If we are in TRANSACTION_PARSE, the given derivation has been retrieved uncrypted (wihtout the help
                //of the device), so continue that way.
                LOG_PRINT_L3( "derive_view_tag  : PARSE mode with known viewkey");
                crypto::derive_view_tag(derivation, output_index, view_tag);
            } else {
                // CALL (derivation/S, output_index)
                DeriveViewTagCommand cmd;
                cmd.req.derivation = derivation;
                cmd.req.output_index = output_index;
                cmd.call();
                CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
                view_tag = cmd.res.view_tag;
                LOG_PRINT_L3("<<derive_view_tag " <<static_cast<int>(view_tag.data));
            }
            return true;
        }


        /* ======================================================================= */
        /*                               TRANSACTION                               */
        /* ======================================================================= */

        void device_sidekick::generate_tx_proof(const crypto::hash &prefix_hash, 
                                               const crypto::public_key &R, const crypto::public_key &A, const boost::optional<crypto::public_key> &B, const crypto::public_key &D, const crypto::secret_key &r, 
                                               crypto::signature &sig) {
            LOG_PRINT_L3(">>generate_tx_proof " << prefix_hash
                                 << R
                                 << A
                                 << B.value_or(crypto::null_pkey)
                                 << D
                                 << r);
            // CALL (prefix_hash, R, A, B, D, r/S)
            GenerateTxProofCommand cmd;
            cmd.req.prefix_hash = prefix_hash;
            cmd.req.R = R;
            cmd.req.A = A;
            cmd.req.has_B = B.has_value();
            cmd.req.B = B.value_or(crypto::null_pkey);
            cmd.req.D = D;
            cmd.req.rr = r;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            sig = cmd.res.sig;
            LOG_PRINT_L3("<<generate_tx_proof " << sig);
        }

        bool device_sidekick::open_tx(crypto::secret_key &tx_key) {
            LOG_PRINT_L3(">>open_tx");
            this->lock();
            // CALL () => tx_key/S, (fake_b)/S, (fake_a)/S - open
            OpenTxCommand cmd;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            tx_key = cmd.res.tx_key;
            CHECK_AND_ASSERT_THROW_MES(!memcmp(cmd.res.spend_key.data, FAKE_SECRET_SPEND_KEY, 32), "expected fake spend key");
            CHECK_AND_ASSERT_THROW_MES(!memcmp(cmd.res.view_key.data, FAKE_SECRET_VIEW_KEY, 32), "expected fake view key");
            LOG_PRINT_L3("<<open_tx " <<tx_key);
            return true;
        }

        void device_sidekick::get_transaction_prefix_hash(const cryptonote::transaction_prefix &tx_prefix, crypto::hash &h) {
            LOG_PRINT_L3(">>get_transaction_prefix_hash");
            // log what we have:
            for (size_t i = 0; i < tx_prefix.vout.size(); i++) {
                const cryptonote::txout_to_key* const out_key = boost::get<cryptonote::txout_to_key>(std::addressof(tx_prefix.vout[i].target));
                LOG_PRINT_L3("vout["<<i<<"].target.key=" << out_key->key);
            }
            // CALL (tx)
            GetTxPrefixHashCommand cmd;
            cmd.req.tx_prefix = tx_prefix;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            h = cmd.res.h;
            LOG_PRINT_L3("<<get_transaction_prefix_hash " <<h);
        }

        bool device_sidekick::encrypt_payment_id(crypto::hash8 &payment_id, const crypto::public_key &public_key, const crypto::secret_key &secret_key) {
            LOG_PRINT_L3(">>encrypt_payment_id " <<payment_id<<public_key<<secret_key);
            // CALL (payment_id, public_key, secret_key/S)
            EncryptPaymentidCommand cmd;
            cmd.req.payment_id = payment_id;
            cmd.req.public_key = public_key;
            cmd.req.secret_key = secret_key;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            payment_id = cmd.res.payment_id;
            LOG_PRINT_L3("<<encrypt_payment_id " <<payment_id);
            return true;
        }

        bool device_sidekick::generate_output_ephemeral_keys(const size_t tx_version,
                                                            const cryptonote::account_keys &sender_account_keys, const crypto::public_key &tx_key_pub,  const crypto::secret_key &tx_key,
                                                            const cryptonote::tx_destination_entry &dst_entr, const boost::optional<cryptonote::account_public_address> &change_addr, const size_t output_index,
                                                            const bool &need_additional_txkeys, const std::vector<crypto::secret_key> &additional_tx_keys,
                                                            std::vector<crypto::public_key> &additional_tx_public_keys,
                                                            std::vector<rct::key> &amount_keys,  crypto::public_key &out_eph_public_key,
                                                            const bool use_view_tags, crypto::view_tag &view_tag) {
            LOG_PRINT_L3(">>generate_output_ephemeral_keys");
            CHECK_AND_ASSERT_THROW_MES(tx_version > 1, "TX version not supported " << tx_version);
            GenerateOutputEphemeralKeysCommand cmd;
            cmd.req.tx_version = tx_version;
            cmd.req.tx_key = tx_key;
            cmd.req.tx_key_pub = tx_key_pub;
            cmd.req.Aout = dst_entr.addr.m_view_public_key;
            cmd.req.Bout = dst_entr.addr.m_spend_public_key;
            cmd.req.output_index = output_index;
            cmd.req.is_change = (change_addr && dst_entr.addr == *change_addr);
            cmd.req.is_subaddress = dst_entr.is_subaddress;
            cmd.req.need_additional_tx_key = need_additional_txkeys;
            if (need_additional_txkeys) {
               cmd.req.additional_tx_key = additional_tx_keys[output_index];
            }
            cmd.req.use_view_tags = use_view_tags;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            amount_keys.push_back(rct::sk2rct(cmd.res.amount_key));
            out_eph_public_key = cmd.res.out_eph_public_key;
            if (need_additional_txkeys)
                additional_tx_public_keys.push_back(cmd.res.additional_tx_key_pub);
            view_tag = cmd.res.view_tag;
            LOG_PRINT_L3("<<generate_output_ephemeral_keys " << cmd.res.amount_key<<cmd.res.additional_tx_key_pub<<cmd.res.out_eph_public_key);
            return true;
        }

        rct::key device_sidekick::genCommitmentMask(const rct::key &amount_key) {
            LOG_PRINT_L3(">>genCommitmentMask " << amount_key);
            // CALL (amount_key/S)
            GenCommitmentMaskCommand cmd;
            cmd.req.amount_key = amount_key;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            LOG_PRINT_L3("<<genCommitmentMask " << cmd.res.mask);
            return cmd.res.mask;
        }

        bool device_sidekick::ecdhEncode(rct::ecdhTuple &unmasked, const rct::key &sharedSec, bool is_short_amount) {
            LOG_PRINT_L3(">>ecdhEncode " <<unmasked.amount<<unmasked.mask<<sharedSec<<is_short_amount);
            // CALL (unmasked, sharedSec/S, short_amount)
            EdchEncodeCommand cmd;
            cmd.req.unmasked = unmasked;
            cmd.req.sharedSec = sharedSec;
            cmd.req.is_short_amount = is_short_amount;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            unmasked = cmd.res.masked;
            LOG_PRINT_L3("<<ecdhEncode " <<unmasked.amount<<unmasked.mask);
            return true;
        }

        bool device_sidekick::ecdhDecode(rct::ecdhTuple &masked, const rct::key &sharedSec, bool is_short_amount) {
            LOG_PRINT_L3(">>ecdhDecode " <<masked.amount<<masked.mask<<sharedSec<<is_short_amount);
            // CALL (masked, sharedSec/S, short_amount)
            EdchDecodeCommand cmd;
            cmd.req.masked = masked;
            cmd.req.sharedSec = sharedSec;
            cmd.req.is_short_amount = is_short_amount;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            masked = cmd.res.unmasked;
            LOG_PRINT_L3("<<ecdhDecode " <<masked.amount<<masked.mask);
            return true;
        }

        bool device_sidekick::mlsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size, const rct::keyV &hashes, const rct::ctkeyV &outPk, rct::key &prehash) {
            LOG_PRINT_L3(">>prehash " <<inputs_size<<","<<outputs_size);
            PrehashCommand cmd;
            cmd.req.blob = blob;
            cmd.req.inputs_size = inputs_size;
            cmd.req.outputs_size = outputs_size;
            cmd.req.hashes = hashes;
            cmd.req.outPk = outPk;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            prehash = cmd.res.prehash;
            LOG_PRINT_L3("<<prehash " <<prehash);
            return true;
        }

        bool device_sidekick::clsag_prepare(const rct::key &p, const rct::key &z, rct::key &I, rct::key &D, const rct::key &H, rct::key &a, rct::key &aG, rct::key &aH) {
            LOG_PRINT_L3(">=clsag_prepare");
            // CALL (p/S, z, H) => a/S, aG, aH, I, D
            ClsagPrepareCommand cmd;
            cmd.req.p = p;
            cmd.req.z = z;
            cmd.req.H = H;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            I  = cmd.res.I;
            D  = cmd.res.D;
            a  = cmd.res.a;
            aG = cmd.res.aG;
            aH = cmd.res.aH;
            LOG_PRINT_L3("<<clsag_prepare");
            return true;
        }

        // size_t is long unsinged int
        // size_t keys_size = data.size() * sizeof(rct::key);
        // rct::key* keys = &data[0];
        bool device_sidekick::clsag_hash(const rct::keyV &data, rct::key &hash) {
            LOG_PRINT_L3(">>clsag_hash");
            // CALL (data.bytes) => hash.bytes
            ClsagHashCommand cmd;
            cmd.req.data = data;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            hash = cmd.res.hash;
            LOG_PRINT_L3("<<clsag_hash " <<hash);
            return true;
        }

        bool device_sidekick::clsag_sign(const rct::key &c, const rct::key &a, const rct::key &p, const rct::key &z, const rct::key &mu_P, const rct::key &mu_C, rct::key &s) {
            LOG_PRINT_L3(">>clsag_sign");
            // CALL (a/S, p/S, z, mu_P, mu_C) => s
            ClsagSignCommand cmd;
            // ignore c
            cmd.req.a = a;
            cmd.req.p = p;
            cmd.req.z = z;
            cmd.req.mu_P = mu_P;
            cmd.req.mu_C = mu_C;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            s = cmd.res.s;
            LOG_PRINT_L3("<<clsag_sign " <<s);
            return true;
        }

        bool device_sidekick::close_tx() {
            LOG_PRINT_L3(">>close_tx");
            // CALL() - close
            CloseTxCommand cmd;
            cmd.call();
            CHECK_AND_ASSERT_THROW_MES(cmd.res.rc == RC_OK, "device call failed rc=" << cmd.res.rc);
            this->unlock();
            LOG_PRINT_L3("<<close_tx");
            return true;
        }

        /* ---------------------------------------------------------- */
        device_sidekick* device_sidekick::instance = nullptr;
        device_sidekick* device_sidekick::Instance() {
            if (!instance) {
                instance = new device_sidekick();
                instance->set_name("Sidekick");
                instance->set_mode(hw::device::device_mode::NONE);
            }
            return instance;
        };
        void register_all(std::map<std::string, std::unique_ptr<hw::device>> &registry) {
            LOG_PRINT_L3("==register_all");
            registry.insert(std::make_pair("Sidekick", std::unique_ptr<hw::device>(device_sidekick::Instance())));
        }
    }
}
