# Catena-related changes to CONIKS

We changed the CONIKS config file format for both the CONIKS server and the CONIKS test client: 

We changed the Maven `pom.xml` files to add Catena as a dependency. Maven will assume Catena is installed in the local Maven repository, so be sure to run the `install-catena.sh` script from Catena's code repository.

Note that we cannot reuse a Bitcoin private key when testing Catena support in CONIKS or we'll run into errors when `CatenaServer::appendStatement` is called due to ambiguity about which UTXO it should use to append the statement to. This is because we did not implement refunding in Catena yet and we do not deal with more than one UTXO in the Catena wallet.
