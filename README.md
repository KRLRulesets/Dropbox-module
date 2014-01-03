
This module that provides convenience functions for authorizing a KRL application to use Dropbox via OAuth and access the [Dropbox Core API](https://www.dropbox.com/developers/core). 

The file ```dropbox_module_example.krl``` shows how it is used. Both the module and the test ruleset are written so as to minimize the chance of key leakage.  YOu will need to supply your own Drobbox keys in a [keys module](http://developer.kynetx.com/display/docs/Keys) in order to use the example. 

The file ```dropbox_module_test.krl``` is a [test module](http://developer.kynetx.com/display/docs/Test-Driven+Development+and+KRL). You will also have to supply a keys module for the tests if you want to run them.  

The file ```db_keys_sample.krl``` provides a template for the db_keys module.  You will need to:

- put your own Dropbox developer keys in this ruleset and edit the ```provide keys`` pragma to list your own ruleset IDs. 
- host it somewhere secure that has URL access
- register it and update the Dropbox rulesets to reference its RID. 
