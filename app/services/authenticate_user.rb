class AuthenticateUser

  attr_reader :flash

  def initialize(user, params)
    @user = user
    @params = params
    @authenticated = false
    @flash = nil
  end

  def call
    if @user && @user.authenticate(@params[:password]) && @user.enabled?
      @authenticated = true
      @flash = "Welcome back, #{@user.name}!"
    else
      @authenticated = false
      if @user.nil?
        secure_compare_padding
        @flash = 'The email or password you entered was not recognized. Please try again!'
      elsif @user.enabled?
        @flash = 'The email or password you entered was not recognized. Please try again!'
      elsif !@user.enabled?
        @flash = 'Your account has been disabled!'
      end
    end
    self
  end

  def success?
    @authenticated
  end

  private

  def secure_compare_padding
    # user not found so pad response time to mitigate timing attacks & user enumeration
    ActiveSupport::SecurityUtils.secure_compare(
      ::Digest::SHA256.hexdigest(SecureRandom.hex 32),
      ::Digest::SHA256.hexdigest(SecureRandom.hex 32)
    )
  end

end
