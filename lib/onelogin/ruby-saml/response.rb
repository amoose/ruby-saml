require "xml_security"
require "time"
require "nokogiri"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    class Response
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
      DSIG      = "http://www.w3.org/2000/09/xmldsig#"

      # Encryption related
      PLAINTEXT_ASSERTION_PATH = "/Response/Assertion"
      ENCRYPTED_RESPONSE_PATH = "(/Response/EncryptedAssertion/)|(/Response/EncryptedAssertion/)"
      ENCRYPTED_RESPONSE_DATA_PATH = "./EncryptedData"
      ENCRYPTION_METHOD_PATH = "./EncryptionMethod"
      ENCRYPTED_AES_KEY_PATH = "(./KeyInfo/EncryptedKey/CipherData/CipherValue)|(./KeyInfo/EncryptedKey/CipherData/CipherValue)"
      ENCRYPTED_ASSERTION_PATH = "./CipherData/CipherValue"
      RSA_PKCS1_OAEP_PADDING = 4
      RSA_PKCS1_PADDING = 1
      ENCRYTPION_ALGORITHMS = {
          'http://www.w3.org/2001/04/xmlenc#aes128-cbc' => 'AES-128-CBC',
          'http://www.w3.org/2001/04/xmlenc#aes256-cbc' => 'AES-256-CBC'
      }

      # TODO: This should probably be ctor initialized too... WDYT?
      attr_accessor :settings
      attr_accessor :encrypted

      attr_reader :options
      attr_reader :response
      attr_reader :document

      def initialize(response, options = {})
        raise ArgumentError.new("Response cannot be nil") if response.nil?
        @options  = options
        @response = (response =~ /^</) ? response : Base64.decode64(response)
        @document = REXML::Document.new(@response)
        decrypt_assertion_document
        @document = XMLSecurity::SignedDocument.new(@response)
      end

      def is_valid?
        validate
      end

      def validate!
        validate(false)
      end

      # The value of the user identifier as designated by the initialization request response
      def name_id
        @name_id ||= begin
          node = xpath_first_from_signed_assertion('/a:Subject/a:NameID')
          node.nil? ? nil : node.text
        end
      end

      def sessionindex
        @sessionindex ||= begin
          node = xpath_first_from_signed_assertion('/a:AuthnStatement')
          node.nil? ? nil : node.attributes['SessionIndex']
        end
      end

      # Returns OneLogin::RubySaml::Attributes enumerable collection.
      # All attributes can be iterated over +attributes.each+ or returned as array by +attributes.all+
      #
      # For backwards compatibility ruby-saml returns by default only the first value for a given attribute with
      #    attributes['name']
      # To get all of the attributes, use:
      #    attributes.multi('name')
      # Or turn off the compatibility:
      #    OneLogin::RubySaml::Attributes.single_value_compatibility = false
      # Now this will return an array:
      #    attributes['name']
      def attributes
        @attr_statements ||= begin
          attributes = Attributes.new

          stmt_element = xpath_first_from_signed_assertion('/a:AttributeStatement')
          return attributes if stmt_element.nil?

          stmt_element.elements.each do |attr_element|
            name  = attr_element.attributes["Name"]
            values = attr_element.elements.collect{|e|
              # SAMLCore requires that nil AttributeValues MUST contain xsi:nil XML attribute set to "true" or "1"
              # otherwise the value is to be regarded as empty.
              ["true", "1"].include?(e.attributes['xsi:nil']) ? nil : e.text.to_s
            }

            attributes.add(name, values)
          end

          attributes
        end
      end

      def decoded_response
        @decoded_response ||= assertion_document.to_s
      end

      # When this user session should expire at latest
      def session_expires_at
        @expires_at ||= begin
          node = xpath_first_from_signed_assertion('/a:AuthnStatement')
          parse_time(node, "SessionNotOnOrAfter")
        end
      end

      # Checks the status of the response for a "Success" code
      def success?
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:Response/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.attributes["Value"] == "urn:oasis:names:tc:SAML:2.0:status:Success"
        end
      end

      # Conditions (if any) for the assertion to run
      def conditions
        @conditions ||= xpath_first_from_signed_assertion('/a:Conditions')
      end

      def not_before
        @not_before ||= parse_time(conditions, "NotBefore")
      end

      def not_on_or_after
        @not_on_or_after ||= parse_time(conditions, "NotOnOrAfter")
      end

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(assertion_document, "/p:Response/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node ||= xpath_first_from_signed_assertion('/a:Issuer')
          node.nil? ? nil : node.text
        end
      end

      def assertion_document
        @assertion_document ||= begin
          if document.elements[ENCRYPTED_RESPONSE_PATH]
            if sig_element = document.elements['/Response/Signature']
              sig_element.remove #Skipping signature verification - Assertion is already signed andit will be verified.
            end
            document.elements['/Response/'].add(decrypt_assertion_document)
            document.elements[ENCRYPTED_RESPONSE_PATH].remove
            XMLSecurity::SignedDocument.new(document.to_s)
          else
            document
          end
        end
      end


      def validation_error(message)
        raise ValidationError.new(message)
      end

      def validate(soft = true)
        validate_structure(soft)      &&
        validate_response_state(soft) &&
        validate_conditions(soft)     &&
        assertion_document.validate_document(get_fingerprint, soft) &&
        success?
      end

      def validate_structure(soft = true)
        Dir.chdir(File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'schemas'))) do
          @schema = Nokogiri::XML::Schema(IO.read('saml20protocol_schema.xsd'))
          @xml = Nokogiri::XML(self.document.to_s)
        end
        if soft
          @schema.validate(@xml).map{ return false }
        else
          @schema.validate(@xml).map{ |error| validation_error("#{error.message}\n\n#{@xml.to_s}") }
        end
      end

      def validate_response_state(soft = true)
        if response.empty?
          return soft ? false : validation_error("Blank response")
        end

        if settings.nil?
          return soft ? false : validation_error("No settings on response")
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          return soft ? false : validation_error("No fingerprint or certificate on settings")
        end

        true
      end

      def xpath_first_from_signed_assertion(subelt=nil)
        node = REXML::XPath.first(assertion_document, "/p:Response/a:Assertion[@ID='#{assertion_document.signed_element_id}']#{subelt}", { "p" => PROTOCOL, "a" => ASSERTION })
        node ||= REXML::XPath.first(assertion_document, "/p:Response[@ID='#{assertion_document.signed_element_id}']/a:Assertion#{subelt}", { "p" => PROTOCOL, "a" => ASSERTION })
        node
      end

      def get_fingerprint
        if settings.idp_cert
          cert = OpenSSL::X509::Certificate.new(settings.idp_cert)
          Digest::SHA256.hexdigest(cert.to_der).upcase.scan(/../).join(":")
        else
          settings.idp_cert_fingerprint
        end
      end

      def validate_conditions(soft = true)
        return true if conditions.nil?
        return true if options[:skip_conditions]

        now = Time.now.utc

        if not_before && (now + (options[:allowed_clock_drift] || 0)) < not_before
          return soft ? false : validation_error("Current time is earlier than NotBefore condition")
        end

        if not_on_or_after && now >= not_on_or_after
          return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
        end

        true
      end

      def parse_time(node, attribute)
        if node && node.attributes[attribute]
          Time.parse(node.attributes[attribute])
        end
      end

      def decrypt_assertion_document
        encrypted_assertion = document.elements[ENCRYPTED_RESPONSE_PATH]
        return if encrypted_assertion.nil?
        @encrypted = true
        encrypted_assertion = document.elements[ENCRYPTED_RESPONSE_PATH]
        cipher_data = encrypted_assertion.elements[ENCRYPTED_RESPONSE_DATA_PATH]
        aes_key = retrieve_symmetric_key(cipher_data)
        encrypted_assertion = Base64.decode64(cipher_data.elements[ENCRYPTED_ASSERTION_PATH].text)
        alogrithm = ENCRYTPION_ALGORITHMS[cipher_data.elements[ENCRYPTION_METHOD_PATH].attributes['Algorithm']]
        assertion_plaintext = retrieve_plaintext(encrypted_assertion, aes_key, alogrithm)
        REXML::Document.new(assertion_plaintext)
      end

      def retrieve_symmetric_key(cipher_data)
        cert_rsa = OpenSSL::PKey::RSA.new(options[:private_key], options[:private_key_password])
        encrypted_aes_key_element = cipher_data.elements[ENCRYPTED_AES_KEY_PATH]
        encrypted_aes_key = Base64.decode64(encrypted_aes_key_element.text)
        cert_rsa.private_decrypt(encrypted_aes_key, RSA_PKCS1_PADDING)
      end

      def retrieve_plaintext(cipher_text, key, alogrithm)
        aes_cipher = OpenSSL::Cipher.new(alogrithm).decrypt
        iv = cipher_text[0..15]
        data = cipher_text[16..-1]
        aes_cipher.padding, aes_cipher.key, aes_cipher.iv = 0, key, iv
        assertion_plaintext = aes_cipher.update(data)
        assertion_plaintext << aes_cipher.final
        # We get some problematic noise in the plaintext after decrypting.
        # This quick regexp parse will grab only the assertion and discard the noise.
        assertion_plaintext.match(/(.*<\/(saml:|)Assertion>)/m)[0]
      end
    end
  end
end
