
global class JitHandler implements Auth.SamlJitHandler {
    
    // 8-23-17
    // J Dority
    //This class provides logic for inbound just-in-time provisioning of single sign-on users in your Salesforce organization.
    // SAML Assert takes on user id of Apex Class "run as user" - current user is really administrator
    // Custom Attributes don't allow you to pass all the required fields (Local, Language, TimeZone, EmailEncoding which all happen to be pick lists)
    // If user already exists and is inactive, you must activate the user first or assertion fails
    // Unique user name for SP org - how to manage this. 
    // When we introduce a third party IDP, how does this change?    Custom attribute passing?
    
    private class JitException extends Exception{}
    private void handleUser(boolean create, User u, Map<String, String> attributes,
                            String federationIdentifier, boolean isStandard) {
                                String uid = UserInfo.getUserId();
                                User currentUser = [SELECT LocaleSidKey, LanguageLocaleKey, TimeZoneSidKey, EmailEncodingKey FROM User WHERE Id =: uid];
                                
                                string fid = attributes.get('User.FederationIdentifier');
                                system.debug(fid);
                                
                                if(create) {
                                    if(attributes.containsKey('User.FederationIdentifier')) {
                                        u.FederationIdentifier = attributes.get('User.FederationIdentifier');
                                    } else {
                                        u.FederationIdentifier = federationIdentifier;
                                    }
                                }
                                if(create && attributes.containsKey('User.Username')) {
                                    u.Username = attributes.get('User.Username');
                                }else { 
                                    
                                    //For an update query Id based on FederationIdentifier. JMD
                                    User un = [SELECT Id, isActive FROM user WHERE FederationIdentifier=:fid];
                                    system.debug(un.id);
                                    //Set User to Active and update otherwise inactive state won't allow login                                    
                                    if(un.isActive == false) {
                                        u.isActive = true; 
                                        system.debug(u.isActive);
                                        u.id = un.Id;
                                        update u;
                                    }
                                }
                                
                                if(attributes.containsKey('Profile.Name')) {
                                    String profileName = attributes.get('Profile.Name');
                                    Profile p = [SELECT Id FROM Profile WHERE Name=:profileName];
                                    u.ProfileId = p.Id;
                                }
                                if(attributes.containsKey('User.UserRoleId')) {
                                    String userRole = attributes.get('User.UserRoleId');
                                    UserRole r = [SELECT Id FROM UserRole WHERE Id=:userRole];
                                    u.UserRoleId = r.Id;
                                }
                                if(attributes.containsKey('User.Phone')) {
                                    u.Phone = attributes.get('User.Phone');
                                }
                                if(attributes.containsKey('User.LastName')) {
                                    u.Lastname = attributes.get('User.LastName');
                                }
                                if(attributes.containsKey('User.Alias')) {
                                    u.Alias = attributes.get('User.Alias');
                                }

                                if (attributes.containsKey('User.LocaleSidKey')) {
                                    u.LocaleSidKey = attributes.get('User.LocaleSidKey');
                                } else if (create) {
                                    u.LocaleSidKey = currentUser.LocaleSidKey;
                                }
                                if (attributes.containsKey('User.LanguageLocaleKey')) {
                                    u.LanguageLocaleKey = attributes.get('User.LanguageLocaleKey');
                                } else if (create) {
                                    u.LanguageLocaleKey = currentUser.LanguageLocaleKey;
                                }
                                if (attributes.containsKey('User.Alias')) {
                                    u.Alias = attributes.get('User.Alias');
                                } else if (create) {
                                    String alias = '';
                                    if (u.FirstName == null) {
                                        alias = u.LastName;
                                    } else {
                                        alias = u.FirstName.charAt(0) + u.LastName;
                                    }
                                    if (alias.length() > 5) {
                                        alias = alias.substring(0, 5);
                                    }
                                    u.Alias = alias;
                                }
                                if (attributes.containsKey('User.TimeZoneSidKey')) {
                                    u.TimeZoneSidKey = attributes.get('User.TimeZoneSidKey');
                                } else if (create) {
                                    u.TimeZoneSidKey = currentUser.TimeZoneSidKey;
                                }
                                if (attributes.containsKey('User.EmailEncodingKey')) {
                                    u.EmailEncodingKey = attributes.get('User.EmailEncodingKey');
                                } else if (create) {
                                    u.EmailEncodingKey = currentUser.EmailEncodingKey;
                                    
                                    if(attributes.containsKey('User.Email')) {
                                        u.Email	  = attributes.get('User.Email');
                                    } 
                                            
                                    //JMD
                                    // For a create we tweek the user name to make it unique
                                    // Is there a better way to manage this???
                                    system.debug(u.federationIdentifier);
                                    u.username = u.username + '2';
                                    
                                    if(!create) {
                                        
                                        update(u);
                                    }
                                }
                            }
    private void handleJit(boolean create, User u, Id samlSsoProviderId, Id communityId, Id portalId,
                           String federationIdentifier, Map<String, String> attributes, String assertion) {
                               
                               handleUser(create, u, attributes, federationIdentifier, true);
                               
                           }
    
    global User createUser(Id samlSsoProviderId, Id communityId, Id portalId,
                           String federationIdentifier, Map<String, String> attributes, String assertion) {
                               User u = new User();
                               handleJit(true, u, samlSsoProviderId, communityId, portalId,
                                         federationIdentifier, attributes, assertion);
                               return u;
                           }
    
    global void updateUser(Id userId, Id samlSsoProviderId, Id communityId, Id portalId,
                           String federationIdentifier, Map<String, String> attributes, String assertion) {
                               User u = [SELECT Id FROM User WHERE Id=:userId];
                               handleJit(false, u, samlSsoProviderId, communityId, portalId,
                                         federationIdentifier, attributes, assertion);
                           }
}