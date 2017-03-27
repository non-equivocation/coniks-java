/*
  Copyright (c) 2015-16, Princeton University.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:
  * Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following disclaimer
  in the documentation and/or other materials provided with the
  distribution.
  * Neither the name of Princeton University nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
 */

package org.coniks.coniks_server;

// coniks-java imports
import org.coniks.crypto.Digest;
import org.coniks.util.Logging;
import org.coniks.coniks_common.MsgType;
import org.coniks.coniks_common.C2SProtos.*;

import org.coniks.coniks_common.UtilProtos.*;

import java.security.interfaces.DSAPublicKey;

import java.util.ArrayList;
import java.util.Timer;
import java.util.PriorityQueue;
import java.util.TimerTask;
import java.util.Date;
import java.util.Scanner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.lang.NumberFormatException;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;

import com.google.protobuf.*;
import org.javatuples.*;
import java.util.Arrays;

import org.bitcoinj.core.DumpedPrivateKey;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;

import org.catena.common.SimpleWallet;
import org.catena.server.CatenaServer;

/** Implements the main CONIKS server operations:
 * interface to client, initiates Merkle tree rebuilding
 * and signed tree root (STR) generation.
 *
 *@author Marcela S. Melara (melara@cs.princeton.edu)
 *@author Aaron Blankstein
 *@author Michael Rochlin
 */
public class ConiksServer{

    // Must be passed in as args to the server!
    private static String configFileName;
    private static String logPath;
    private static boolean isFullOp;
    private static final int NUM_ARGS = 3; // ha, don't forget to set this to the right number

    private static int providerID; // meant to be SP ID to identify different SP's quickly
    private static Timer epochTimer = new Timer("epoch timer", false); // may wish to run as daemon later

    private static long initEpoch;
    
    private static CatenaServer catServer;
    private static NetworkParameters params = TestNet3Params.get();

    /** Initialize the directory: get the latest root node from the
     * database (if using one) and update the directory internally (i.e. build the hash tree)
     * Because users are stored in lexicographic order, we can simply load them all at once.
     * N.B. Designed for few restarts in mind.
     */
    private static RootNode initDirectory(){
        PriorityQueue<Triplet<byte[], UserLeafNode, Operation>> initUsers =
            new PriorityQueue<Triplet<byte[], UserLeafNode, Operation>>(
                16384, new ServerUtils.PrefixComparator());

        // At this point, if we're using a DB, we want to check if we already have
        // a commitment history stored in the DB
        // if so, retrieve the latest commitment and root node stored in the DB

        RootNode initRoot = TreeBuilder.copyExtendTree(null, initUsers);

        initUsers.clear();

        return initRoot;
    }

    /** Prints server status and error messages.
     * Used primarily for testing mode.
     *
     *@param isErr indicates whether this is an error message
     *@param msg the status message to print
     */
    private static void printStatusMsg (boolean isErr, String msg) {
        String status = msg;
        if (isErr) {
            status = "Error: "+status;
        }

        System.out.println(status);
    }

    /** Configures the server and begins listening for
     * incoming connections from CONIKS clients.
     *<p>
     * Usage:
     * {@code ./coniks_server.sh <start | test | stop | clean>}
     */
    public static void main(String[] args){

        if (args.length != NUM_ARGS) {
            System.out.println("Need "+(NUM_ARGS-1)+" arguments: CONIKS_SERVERCONFIG, and CONIKS_SERVERLOGS");
            System.out.println("The run script may expect these to be passed as env vars, make sure to export these before running the run script again.");
            System.exit(-1);
        }

        File configFile = null;
        try {
            configFileName = args[0];
            configFile = new File(configFileName);

            logPath = args[1];
            File logDir = new File(logPath);

            if (!configFile.exists() || !logDir.isDirectory()) {
                throw new FileNotFoundException();
            }

            String opMode = args[2];
            if (opMode.equalsIgnoreCase("full")) {
                isFullOp = true;
            }
            else if (opMode.equalsIgnoreCase("test")) {
                isFullOp = false;
            }
            else {
                System.out.println("Unknown operation mode: "+opMode);
                System.exit(-1);
            }
        }
        catch (NumberFormatException e) {
            System.out.println("CONIKS_INIT_SIZE must be an integer.");
            System.exit(-1);
        }
        catch (FileNotFoundException e) {
            System.out.println("The path you entered for CONIKS_SERVERCONFIG or CONIKS_SERVERLOGS doesn't exist.");
            System.exit(-1);
        }

        // false indicates an error, so exit

        Logging.setup(logPath+"/server-%g", "Server");
        if (!ServerConfig.readServerConfig(configFile, isFullOp)) {
            System.exit(-1);
        }

        // set some more configs
        initEpoch = ServerConfig.getStartupTime();

        System.setProperty("javax.net.ssl.keyStore", ServerConfig.getKeystorePath());
        System.setProperty("javax.net.ssl.keyStorePassword", ServerConfig.getKeystorePassword());

        // this is needed to set up the SSL connection
        if (isFullOp) {
            System.setProperty("javax.net.ssl.trustStore", ServerConfig.getTruststorePath());
            System.setProperty("javax.net.ssl.trustStorePassword", ServerConfig.getTruststorePassword());
        }

        RootNode initRoot = initDirectory(); // initializes the directory

        // check that we got a good first tree
        if(initRoot == null) {
            if (isFullOp) {
                Logging.error("An error occured while trying to build the initial tree");
            }
            else {
                printStatusMsg(true, "An error occured while trying to build the initial tree");
            }
            // just bail
            System.exit(-1);
        }

        // init the history
         if (!ServerHistory.initHistory(initRoot, initEpoch, 0,
                                       new byte[Digest.HASH_SIZE_BYTES])) {
            printStatusMsg(true, "Error initializing the history");
            System.exit(-1);
         }
         
         // Initialize the Catena log server
         Sha256Hash txid = Sha256Hash.wrap(ServerConfig.CATENA_GENESIS_TXID);
         ECKey chainKey = DumpedPrivateKey.fromBase58(params, ServerConfig.CATENA_STMT_KEY).getKey();
         try {
             catServer = new CatenaServer(params, new File("catena-server"), chainKey, txid);
             
             // Download the block chain and wait until it's done.
             catServer.startAsync();
             catServer.awaitRunning();
             Logging.log("Wallet balance: " + catServer.getCatenaWallet().getBalance().toFriendlyString());
             
         } catch (Exception e) {
             throw new RuntimeException("Failed setting up Catena log server: " + e);
         }

        EpochTimerTask epochSnapshotTaker = new EpochTimerTask();

        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleWithFixedDelay(epochSnapshotTaker,
                                         ServerConfig.getEpochInterval(),
                                         ServerConfig.getEpochInterval(),
                                         TimeUnit.MILLISECONDS);

        ServerMessaging.listenForRequests(isFullOp);

    }

    /** Implements a TimerTask that updates the STR history every epoch.
     */
    private static class EpochTimerTask implements Runnable {

        public void run() {
            Logging.log("Timer task started.");
            try {
                RootNode nextRoot = DirectoryOps.updateDirectory();
    
                // check that we got a good first tree
                if(nextRoot == null) {
                    if (isFullOp) {
                        Logging.error("An error occured while trying to update the tree");
                    }
                    else {
                        printStatusMsg(true, "An error occured while trying to update the tree");
                    }
                    // let's not quite bail here
                    throw new UnsupportedOperationException("Next root was null");
                }
    
                // this should approximately be EPOCH_INTERVAL millis since the last call
                long nextEpoch = System.currentTimeMillis();
    
                SignedTreeRoot nextSTR = TransparencyOps.generateNextSTR(nextRoot, nextEpoch);
                
                // Publish STR to Catena log, except we publish the hash of the signature 
                // (RSA sigs are 256 bytes > 80 bytes OP_RETURN payload limit)
                try {
                    byte[] hashedSig = Digest.digest(nextSTR.getSignature());
                    Logging.log("Preparing to issue Catena statement...");
                    catServer.appendStatement(hashedSig);
                    Logging.log("Done issuing Catena statement!");
                } catch (Throwable e) {
                    Logging.error("An error occured while publishing STR to Catena log: " + e);
                }
    
                if (!ServerHistory.updateHistory(nextSTR)) {
                    if (isFullOp) {
                        Logging.error("An error occured while trying to update the tree");
                    }
                    else {
                        printStatusMsg(true, "An error occured while trying to update the tree");
                    }
                    // let's not quite bail here
                    throw new UnsupportedOperationException("Next STR was null or malformed");
                }
    
                // we're here so the update went well
                if (isFullOp) {
                    Logging.log("Directory update successful. Next epoch: "+nextEpoch);
                }
                else {
                    printStatusMsg(false, "Directory update successful. Next epoch: "+nextEpoch);
                }
            } catch (Throwable e) {
                Logging.error("Exception in timer task: " + e);
                e.printStackTrace();
            }
        }

    }

}
