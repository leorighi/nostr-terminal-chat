package main

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
)

const (
	relayURL    = "wss://relay.damus.io"
	receiverPub = "npub1c0qyae9ggdxmrs9gnpkrc5t0dzncfgypvmrx9rzygclzyld5q4nqe9ja8j" //Receiver public key
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privateKey := nostr.GeneratePrivateKey()
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		panic(err)
	}

	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		panic(err)
	}

	receiverPubDecoded := decodePublicKey(receiverPub)

	go receiveMessages(ctx, relay, receiverPubDecoded, privateKey)

	handleUserInput(ctx, relay, publicKey, receiverPubDecoded, privateKey)
}

func decodePublicKey(encodedKey string) string {
	_, decodedKey, err := nip19.Decode(encodedKey)
	if err != nil {
		panic(err)
	}
	return decodedKey.(string)
}

func receiveMessages(ctx context.Context, relay *nostr.Relay, receiverPub string, senderPrivateKey string) {
	sharedKey, err := nip04.ComputeSharedSecret(receiverPub, senderPrivateKey)
	if err != nil {
		panic(err)
	}

	senderPublicKey, err := nostr.GetPublicKey(senderPrivateKey)
	if err != nil {
		panic(err)
	}

	filters := []nostr.Filter{{
		Kinds:   []int{nostr.KindEncryptedDirectMessage},
		Authors: []string{receiverPub},
		Tags:    nostr.TagMap{"p": {senderPublicKey}},
	}}

	subscription, err := relay.Subscribe(ctx, filters)
	if err != nil {
		panic(err)
	}
	defer subscription.Close()

	messageHandler(ctx, subscription, sharedKey)
}

func messageHandler(ctx context.Context, subscription *nostr.Subscription, sharedKey []byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-subscription.Events:
			if event.Kind == nostr.KindEncryptedDirectMessage {
				decryptedMessage, err := nip04.Decrypt(event.Content, sharedKey)
				if err != nil {
					panic(err)
				}
				fmt.Printf("\rMessage received: %s\nSend Message: ", decryptedMessage)
			}
		}
	}
}

func handleUserInput(ctx context.Context, relay *nostr.Relay, senderPub string, receiverPub string, senderPrivateKey string) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Send Message: ")
	for scanner.Scan() {
		message := scanner.Text()
		if err := sendMessage(ctx, relay, senderPub, receiverPub, senderPrivateKey, message); err != nil {
			fmt.Printf("Error sending message: %s\n", err)
			fmt.Print("Send Message: ")
			continue
		}
		fmt.Printf("\rMessage sent: %s\n", message)
		fmt.Print("Send Message: ")
	}
}

func sendMessage(ctx context.Context, relay *nostr.Relay, senderPub string, receiverPub string, senderPrivateKey string, message string) error {
	sharedKey, err := nip04.ComputeSharedSecret(receiverPub, senderPrivateKey)
	if err != nil {
		return err
	}

	encryptedMessage, err := nip04.Encrypt(message, sharedKey)
	if err != nil {
		return err
	}

	event := nostr.Event{
		PubKey:    senderPub,
		CreatedAt: nostr.Now(),
		Kind:      nostr.KindEncryptedDirectMessage,
		Tags:      nostr.Tags{{"p", receiverPub}},
		Content:   encryptedMessage,
	}

	event.Sign(senderPrivateKey)

	return relay.Publish(ctx, event)
}
