class User < ApplicationRecord
    attr_reader :password
    validates :password, length: { minimum: 6 }, allow_nil: true

    def password=(password)
        @password = password
        self.password_digest = BCrypt::Password.create(password)
    end

    def is_password?(password)
        output = BCrypt::Password.new(self.password_digest)
        output.is_password?(password)
    end

    def self.find_by_credentials(username, password)
        @user = User.find_by(username: username)
        if @user && @user.is_password?(password)
            return @user
        else
            return nil
        end
    end

    def reset_session_token!
        self.session_token = generate_unique_session_token
        self.save!
        self.session_token
    end

    private
    def generate_unique_session_token
        token = SecureRandom::urlsafe_base64
        while User.exists?(session_token: token)
            token = SecureRandom::urlsafe_base64
        end
        token
    end

    def ensure_session_token
        self.session_token ||= generate_unique_session_token
    end
end
