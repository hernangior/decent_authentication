source 'https://rubygems.org'

ruby '2.6.5'

git_source(:github) { |repo| "https://github.com/#{repo}.git" }

gem 'bcrypt'
gem 'bootsnap', require: false
gem 'hamlit'
gem 'pg'
gem 'rails'
gem 'sassc-rails'
gem 'uglifier', '>= 1.3.0'

group :development, :test do
  gem 'awesome_print'
  gem 'factory_bot_rails'
  gem 'pry-byebug'
  gem 'pry-rails'
  gem 'rspec-rails'
  gem 'rubocop', require: false
  gem 'rubocop-performance'
  gem 'rubocop-rails'
  gem 'rubocop-rspec'
end

group :development do
  gem 'better_errors'
  gem 'binding_of_caller'
  gem 'brakeman', require: false
  gem 'rails_best_practices'
  gem 'spring'
  gem 'thin'
end

group :test do
  gem 'capybara'
  gem 'email_spec'
  gem 'launchy'
  gem 'rake'
  gem 'selenium-webdriver'
  gem 'shoulda-matchers'
  gem 'simplecov', require: false
end
