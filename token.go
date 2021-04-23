package dynamo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"gopkg.in/mgo.v2/bson"
)

func NewTokenStore(config *Config) (store oauth2.TokenStore) {
	awsConf := config.AWSCONFIG
	svc := dynamodb.NewFromConfig(*awsConf)
	return &TokenStore{
		config:  config,
		session: svc,
	}
}

type TokenStore struct {
	config  *Config
	session *dynamodb.Client
}

type tokenData struct {
	ID        string    `json:"_id"`
	BasicID   string    `json:"BasicID"`
	ExpiredAt time.Time `json:"ExpiredAt"`
}

type basicData struct {
	ID        string    `json:"_id"`
	Data      []byte    `json:"Data"`
	ExpiredAt time.Time `json:"ExpiredAt"`
}

// Create and store the new token information
func (tokenStorage *TokenStore) Create(
	ctx context.Context, info oauth2.TokenInfo,
) (err error) {
	if code := info.GetCode(); code != "" {
		err = CreateWithAuthorizationCode(tokenStorage, info, "")
		if err != nil {
			fmt.Printf("CreateWithAuthorizationCode error: %s\n", err)
		}
		return
	}
	if refresh := info.GetRefresh(); refresh != "" {
		err = CreateWithRefreshToken(tokenStorage, info)
	} else {
		err = CreateWithAccessToken(tokenStorage, info, "")
	}
	return
}

func CreateWithAuthorizationCode(
	tokenStorage *TokenStore, info oauth2.TokenInfo, id string,
) (err error) {
	code := info.GetCode()
	if len(id) > 0 {
		code = id
	}
	data, err := json.Marshal(info)
	if err != nil {
		return
	}
	expiredAt := info.GetCodeCreateAt().Add(info.GetCodeExpiresIn())
	rExpiredAt := expiredAt
	if refresh := info.GetRefresh(); refresh != "" {
		rexp := info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn())
		if expiredAt.Second() > rexp.Second() {
			expiredAt = rexp
		}
		rExpiredAt = rexp
	}
	exp := rExpiredAt.Format(time.RFC3339)

	items, err := attributevalue.MarshalMap(map[string]interface{}{
		"ID":        code,
		"Data":      data,
		"ExpiredAt": exp,
	})
	if err != nil {
		return
	}

	params := &dynamodb.PutItemInput{
		TableName: aws.String(tokenStorage.config.TABLE.BasicCname),
		Item:      items,
	}
	_, err = tokenStorage.session.PutItem(context.Background(), params)
	return
}

func CreateWithAccessToken(
	tokenStorage *TokenStore, info oauth2.TokenInfo, id string,
) (err error) {
	if len(id) == 0 {
		id = bson.NewObjectId().Hex()
	}
	err = CreateWithAuthorizationCode(tokenStorage, info, id)
	if err != nil {
		return
	}
	expiredAt := info.GetAccessCreateAt().
		Add(info.GetAccessExpiresIn()).Format(time.RFC3339)

	items, err := attributevalue.MarshalMap(map[string]interface{}{
		"ID":        info.GetAccess(),
		"BasicID":   id,
		"ExpiredAt": expiredAt,
	})
	if err != nil {
		return
	}

	accessParams := &dynamodb.PutItemInput{
		TableName: aws.String(tokenStorage.config.TABLE.AccessCName),
		Item:      items,
	}
	_, err = tokenStorage.session.PutItem(context.Background(), accessParams)
	return
}

func CreateWithRefreshToken(
	tokenStorage *TokenStore, info oauth2.TokenInfo,
) (err error) {
	id := bson.NewObjectId().Hex()
	err = CreateWithAccessToken(tokenStorage, info, id)
	if err != nil {
		return
	}
	expiredAt := info.GetRefreshCreateAt().
		Add(info.GetRefreshExpiresIn()).Format(time.RFC3339)

	items, err := attributevalue.MarshalMap(map[string]interface{}{
		"ID":        info.GetRefresh(),
		"BasicID":   id,
		"ExpiredAt": expiredAt,
	})
	if err != nil {
		return
	}

	refreshParams := &dynamodb.PutItemInput{
		TableName: aws.String(tokenStorage.config.TABLE.RefreshCName),
		Item:      items,
	}
	_, err = tokenStorage.session.PutItem(context.Background(), refreshParams)
	return
}

// RemoveByCode use the authorization code to delete the token information
func (tokenStorage *TokenStore) RemoveByCode(
	ctx context.Context, code string,
) (err error) {
	key, err := attributevalue.MarshalMap(map[string]interface{}{"ID": code})
	if err != nil {
		return
	}

	input := &dynamodb.DeleteItemInput{
		Key:       key,
		TableName: aws.String(tokenStorage.config.TABLE.BasicCname),
	}
	_, err = tokenStorage.session.DeleteItem(ctx, input)
	if err != nil {
		fmt.Printf("RemoveByCode error: %s\n", err.Error())
	}
	return
}

// RemoveByAccess use the access token to delete the token information
func (tokenStorage *TokenStore) RemoveByAccess(
	ctx context.Context, access string,
) (err error) {
	key, err := attributevalue.MarshalMap(map[string]interface{}{"ID": access})
	if err != nil {
		return
	}

	input := &dynamodb.DeleteItemInput{
		Key:       key,
		TableName: aws.String(tokenStorage.config.TABLE.AccessCName),
	}
	_, err = tokenStorage.session.DeleteItem(ctx, input)
	if err != nil {
		fmt.Printf("RemoveByAccess error: %s\n", err.Error())
	}
	return
}

// RemoveByRefresh use the refresh token to delete the token information
func (tokenStorage *TokenStore) RemoveByRefresh(
	ctx context.Context, refresh string,
) (err error) {
	key, err := attributevalue.MarshalMap(map[string]interface{}{"ID": refresh})
	if err != nil {
		return
	}

	input := &dynamodb.DeleteItemInput{
		Key:       key,
		TableName: aws.String(tokenStorage.config.TABLE.RefreshCName),
	}
	_, err = tokenStorage.session.DeleteItem(ctx, input)
	if err != nil {
		fmt.Printf("RemoveByRefresh error: %s\n", err.Error())
	}
	return
}

func (tokenStorage *TokenStore) getData(
	basicID string,
) (to oauth2.TokenInfo, err error) {
	if len(basicID) == 0 {
		return
	}
	key, err := attributevalue.MarshalMap(map[string]interface{}{"ID": basicID})
	if err != nil {
		return
	}

	input := &dynamodb.GetItemInput{
		TableName:      aws.String(tokenStorage.config.TABLE.BasicCname),
		Key:            key,
		ConsistentRead: aws.Bool(tokenStorage.config.CONSISTENT_READS),
	}
	result, err := tokenStorage.session.GetItem(context.Background(), input)
	if err != nil {
		return
	}
	if len(result.Item) == 0 {
		return
	}
	var b basicData
	err = attributevalue.UnmarshalMap(result.Item, &b)
	if err != nil {
		return
	}
	var tm models.Token
	err = json.Unmarshal(b.Data, &tm)
	if err != nil {
		return
	}
	to = &tm
	return
}

func (tokenStorage *TokenStore) getBasicID(
	cname, token string,
) (basicID string, err error) {
	key, err := attributevalue.MarshalMap(map[string]interface{}{"ID": token})
	if err != nil {
		return
	}

	input := &dynamodb.GetItemInput{
		Key:            key,
		TableName:      aws.String(cname),
		ConsistentRead: aws.Bool(tokenStorage.config.CONSISTENT_READS),
	}
	result, err := tokenStorage.session.GetItem(context.Background(), input)
	if err != nil {
		return
	}
	var td tokenData
	err = attributevalue.UnmarshalMap(result.Item, &td)
	if err != nil {
		return
	}
	basicID = td.BasicID
	return
}

// GetByCode use the authorization code for token information data
func (tokenStorage *TokenStore) GetByCode(
	ctx context.Context, code string,
) (to oauth2.TokenInfo, err error) {
	to, err = tokenStorage.getData(code)
	return
}

// GetByAccess use the access token for token information data
func (tokenStorage *TokenStore) GetByAccess(
	ctx context.Context, access string,
) (to oauth2.TokenInfo, err error) {
	basicID, err := tokenStorage.getBasicID(
		tokenStorage.config.TABLE.AccessCName, access,
	)
	if err != nil && basicID == "" {
		return
	}
	to, err = tokenStorage.getData(basicID)
	return
}

// GetByRefresh use the refresh token for token information data
func (tokenStorage *TokenStore) GetByRefresh(
	ctx context.Context, refresh string,
) (to oauth2.TokenInfo, err error) {
	basicID, err := tokenStorage.getBasicID(tokenStorage.config.TABLE.RefreshCName, refresh)
	if err != nil && basicID == "" {
		return
	}
	to, err = tokenStorage.getData(basicID)
	return
}
