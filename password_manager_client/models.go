package main

import "encoding/json"

type Configuration struct {
	Username     string `json:"username"`
	SymmetricKey string `json:"symmetric_key"`
}

type DatabaseData struct {
	Description   string `json:"description"`
	Username      string `json:"username"`
	EncryptedData string `json:"encrypted_data"`
}

type AccountInfo struct {
	Description string `json:"description"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

func (c *Configuration) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

func ConfigurationFromJSON(data []byte) (*Configuration, error) {
	var c Configuration
	err := json.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (d *DatabaseData) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

func DatabaseDataFromJSON(data []byte) (*DatabaseData, error) {
	var d DatabaseData
	err := json.Unmarshal(data, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (a *AccountInfo) ToJSON() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

func AccountInfoFromJSON(data []byte) (*AccountInfo, error) {
	var a AccountInfo
	err := json.Unmarshal(data, &a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}
