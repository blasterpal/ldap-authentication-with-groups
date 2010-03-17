require "rubygems"
require "net/ldap"  #this is http://github.com/RoryO/ruby-net-ldap  

# This client was created to augment other examples and libraries that exist that authenicate well, but do not check group membership as well. 
# Has been tested against Active Directory Services, have not tested against other LDAP servers.  

class AuthenticateAds
  attr_accessor :ldap_conn, :username, :password, :adshost, :base_dn_arr, :base_dn,:search_filter_attr,:member_of_group,:treebase

  #create a constructor which takes all relevant parameters and saves them
  #to their corresponding attributes
  def initialize(username, password, adshost, base_dn,search_filter_attr)
    @username = username
    @password = password
    @adshost = adshost 
    @base_dn = base_dn
    @base_dn_arr = @base_dn.split('.')
    @treebase = @base_dn_arr.collect{|this_d|"dc=#{this_d}"}.join(",")    
    @search_filter_attr = search_filter_attr
    @member_of_group = member_of_group
  end

  #validates the user against Active Directory and returns a boolean value stating
  #whether the user was successfully authenticated or not.
  def valid_user?
    #create a new LDAP object using the ruby-net-ldap library
    @ldap_conn = Net::LDAP.new(:base => @treebase,
      :host => @adshost,
      :auth => {:username => "#{@username}@#{@base_dn}",
        :password => @password,
        :method => :simple})
    #return a boolean indicating whether authentication was successful or not
    return @ldap_conn.bind
  end

  def valid_user_and_in_group?(group_cn)
    #authenticate user, only if that succeeds will be checked for membership
    #within the specified group cn
    if valid_user?    
      filter = Net::LDAP::Filter.eq( @search_filter_attr, @username  )
      attrs = [  @search_filter_attr, "objectclass", "memberOf"]
      results = @ldap_conn.search( :base => @treebase, :filter => filter, :attributes => attrs, :return_result => true )       
      group_names = results.first[:memberof]     
      return group_names.any?{|name| name == group_cn}
    end  
    #the user membership in the specified group could not be verified
    return false
  end 

end

