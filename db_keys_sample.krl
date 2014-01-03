ruleset db_keys {
  meta {
    name "Dropbox keys sample"
    description <<
These are the keys for testing. This file should not be on a publically available URL
    >>
    author "Phil Windley"
    logging off

    key dropbox {
       "app_key" : "<redacted>",
       "app_secret" : "<redacted>"
    }      
    
    // change these ruleset IDs to the ones you register for your apps that use Dropbox
    provide keys dropbox to a16x175, b16x6
  }

}