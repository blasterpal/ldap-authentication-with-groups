require 'rubygems'
require "yaml"
require 'highline/import'
require 'authenticate_ldap'

def get_user(prompt="Enter your Active Directory email name (e.g. hank.beaver) for Primedia Domain")
   ask(prompt) {|q| q.echo = true}
end

def get_password(prompt="Enter your Active Directory password")
   ask(prompt) {|q| q.echo = false}
end 

@config = YAML.load_file( 'ldap.yml' )
 
@ldap_auth = AuthenticateAds.new(get_user,get_password,@config['ldap']['host'],@config['ldap']['base_dn'],@config['ldap']['search_filter_attr']
) 

puts "Checking for membership of #{@config['ldap']['member_of_group']}:"
puts @ldap_auth.valid_user_and_in_group?(@config['ldap']['member_of_group']  )  
                    