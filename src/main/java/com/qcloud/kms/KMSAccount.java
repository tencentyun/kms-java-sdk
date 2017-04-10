package com.qcloud.kms;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.Vector;
import java.lang.Integer;

import com.qcloud.kms.KeyMetadata.*;
import com.qcloud.kms.KMSServerException.*;
import com.qcloud.kms.Json.*;
import com.qcloud.kms.KMSTool.*;

/**
 * @file KMSAccount.java
 * @author:yorkxyzhang
 * @Description:KMSAccount class 
 * @date :2017-2-28
 **/
public class KMSAccount {
    protected KMSClient client;
    public KMSAccount(String endpoint , String secretId, String secretKey)
    {
    	this.client = new KMSClient(endpoint, "/v2/index.php", secretId, secretKey, "POST");
    }

    public KMSAccount(String secretId, String secretKey,String endpoint, String path, String method)
    {
		this.client = new KMSClient(endpoint, path, secretId, secretKey, method);
	}

    /**
     * setSignMethod set the sign meth and now we suppport sha1 and sha256
     * @signMethod  sign method now only set sha1 or sha256
     **/
    
    public void setSignMethod(String signMethod)
    {
    	this.client.setSignMethod(signMethod);
    }
    /**
     * create_key   create qcloud master key
     * @Description key description
     * @Alias       key alias name.
     * @KeyUsage:   the usage of the key default 'ENCRYPT/DECRYPT'
     * return       KeyMetadata  
     **/
    public KeyMetadata create_key(String Description,String Alias ,String KeyUsage) throws Exception
    {
    	TreeMap<String, String> param = new TreeMap<String, String>();
		param.put("description",Description);
		param.put("alias",Alias);
		param.put("keyUsage",  KeyUsage);
		String result = this.client.call("CreateKey", param);
		JSONObject jsonObj = new JSONObject(result);
		int code = jsonObj.getInt("code");
		if(code != 0)
			throw new KMSServerException(code,jsonObj.getString("message"),jsonObj.getString("requestId"));
        JSONObject metaObj = new JSONObject(jsonObj.getString("keyMetadata"));
	    KeyMetadata meta = new KeyMetadata();
	    meta.KeyId   = metaObj.getString("keyId");
	    meta.CreateTime = metaObj.getInt("createTime");
	    meta.Description = metaObj.getString("description");
	    meta.KeyState = metaObj.getString("keyUsage");
	    meta.Alias = metaObj.getString("alias");
	    meta.KeyUsage = metaObj.getString("keyUsage");
	    return meta;
    }
    /**
     * generate_data_key   generate_data_key by the custom master key
     * @KeyId              the custom master key id
     * @KeySpec            AES_128 or AES_256
     * @NumberOfBytes      the size of the data key 1-1024B
     * @EncryptionContext  the json string context
     * @Plaintext          the data key string   
     * return              CiphertextBlob   the encrypted data key string
     **/
    public String generate_data_key(String KeyId, String KeySpec, int NumberOfBytes , String EncryptionContext,String Plaintext ) throws Exception
    {
    	TreeMap<String,String> param = new TreeMap<String ,String>();
    	param.put("keyId",KeyId);
    	param.put("keySpec",KeySpec);
    	param.put("numberOfBytes",Integer.toString(NumberOfBytes));
    	if (EncryptionContext != null)
    	    param.put("encryptionContext", EncryptionContext);
    	String result = this.client.call("GenerateDataKey",param);
    	JSONObject jsonObj = new JSONObject(result);
    	int code = jsonObj.getInt("code");
		if(code != 0)
			throw new KMSServerException(code,jsonObj.getString("message"),jsonObj.getString("requestId"));
		Plaintext = KMSTool.base64_decode(jsonObj.getString("plaintext"));
		return jsonObj.getString("ciphertextBlob");
    }
    /**
     * encrypt             encrypt plaintext
     * @keyid              the custom key id
     * @plaintext          the data string
     * @EncryptionContext  the json string context if you provide it here , you must provide the same when decrypt the data
     * return              the data string encryped
     **/
    public String encrypt(String KeyId, String Plaintext, String EncryptionContext) throws Exception
    {
    	TreeMap<String ,String> param = new TreeMap<String,String>();
    	param.put("keyId", KeyId);
    	param.put("plaintext",KMSTool.base64_encode(Plaintext));
    	if (EncryptionContext != null)
    	    param.put("encryptionContext", EncryptionContext);
    	String result = this.client.call("Encrypt",param);
    	JSONObject jsonObj = new JSONObject(result);
    	int code = jsonObj.getInt("code");
		if(code != 0)
			throw new KMSServerException(code,jsonObj.getString("message"),jsonObj.getString("requestId"));

		return jsonObj.getString("ciphertextBlob");
    }
    /**
	 * decrypt               decrypt the data string
	 * @CiphertextBlob       the encryped data string
	 * @EncryptionContext    the json string context
	 * return                the data string
	 **/
    public String decrypt(String CiphertextBlob , String EncryptionContext)throws Exception
    {
    	TreeMap<String , String > param = new TreeMap<String ,String>(); 	
    	param.put("ciphertextBlob",CiphertextBlob);
    	if (EncryptionContext != null)
    	    param.put("encryptionContext", EncryptionContext);
    	String result = this.client.call("Decrypt",param);
    	JSONObject jsonObj = new JSONObject(result);
    	int code = jsonObj.getInt("code");
		if(code != 0)
			throw new KMSServerException(code,jsonObj.getString("message"),jsonObj.getString("requestId"));
		return KMSTool.base64_decode(jsonObj.getString("plaintext"));
    }
    /**
	 * list_key           list the custom key
	 * @offset            default = 0
	 * @limit             default = 10
	 * @KeyList           key list 
	 * return             void
	 **/
    public void  list_key(int offset, int limit,List<String> KeyList) throws Exception
    {
    	TreeMap<String ,String> param = new TreeMap<String,String>();
    	if(offset > 0)
    	    param.put("offset",Integer.toString(offset));
    	if(limit > 0)
    	    param.put("limit",Integer.toString(limit));
    	String result = this.client.call("ListKey",param);
    	JSONObject jsonObj = new JSONObject(result);
    	int code = jsonObj.getInt("code");
    	if(code != 0)
    		throw new KMSServerException(code,jsonObj.getString("message"),jsonObj.getString("requestId"));
    	JSONArray jsonArray = jsonObj.getJSONArray("keys");
    	for(int i = 0 ; i < jsonArray.length() ; ++i)
    	{
    		JSONObject obj = (JSONObject)jsonArray.get(i);
    		KeyList.add(obj.getString("keyId"));

    	}
    }
	/**
	 * disable_key           disable the custom key
	 * @KeyId                the custom key id
	 * return                void
	 **/
    public void disable_key(String KeyId) throws Exception
    {
    	TreeMap<String ,String> param = new TreeMap<String ,String>();
    	if(KeyId != null)
    	    param.put("keyId",KeyId);
    	String result = this.client.call("DisableKey",param);
    	JSONObject jsonObj = new JSONObject(result);
    	int code = jsonObj.getInt("code");
		if(code != 0)
			throw new KMSServerException(code,jsonObj.getString("message"),jsonObj.getString("requestId"));

    }
	/**
	 * enable_key          enable the custom key
	 * @KeyId              the custom key id
	 * return              void
	 **/
    public void enable_key(String KeyId) throws Exception
    {
    	TreeMap<String, String> param = new TreeMap<String, String>();
    	if(KeyId != null)
		    param.put("keyId",KeyId);
		String result = this.client.call("EnableKey", param);
		JSONObject jsonObj = new JSONObject(result);
		int code = jsonObj.getInt("code");
		if(code != 0)
			throw new KMSServerException(code,jsonObj.getString("message"),jsonObj.getString("requestId"));
    }
	/**
	 * get_key_attributes get the custom key meta
	 * @keyid             the custom key id
	 * return             KeyMetadata
	 **/
    public KeyMetadata get_key_attributes(String KeyId) throws Exception
    {
    	TreeMap<String, String> param = new TreeMap<String, String>();
    	if(KeyId != null)
		    param.put("keyId",KeyId);
		String result = this.client.call("GetKeyAttributes", param);
		JSONObject jsonObj = new JSONObject(result);
		int code = jsonObj.getInt("code");
		if(code != 0)
			throw new KMSServerException(code,jsonObj.getString("message"),jsonObj.getString("requestId"));
		JSONObject metaObj = new JSONObject(jsonObj.getString("keyMetadata"));
	    KeyMetadata meta = new KeyMetadata();
	    meta.KeyId   = metaObj.getString("keyId");
	    meta.CreateTime = metaObj.getInt("createTime");
	    meta.Description = metaObj.getString("description");
	    meta.KeyState = metaObj.getString("keyUsage");
	    meta.Alias = metaObj.getString("alias");
	    meta.KeyUsage = metaObj.getString("keyUsage");
	    return meta;
    }
	/**
	 * set_key_attributes  set key attributes only support setting alias
	 * @keyid              the custom key id
	 * @Alias              the alias
	 * return              void 
	 **/
    public void set_key_attributes(String KeyId , String Alias) throws Exception
    {
    	TreeMap<String, String> param = new TreeMap<String, String>();
		param.put("keyId",KeyId);
		param.put("alias",Alias);
		String result = this.client.call("SetKeyAttributes", param);
		JSONObject jsonObj = new JSONObject(result);
		int code = jsonObj.getInt("code");
		if(code != 0)
			throw new KMSServerException(code,jsonObj.getString("message"),jsonObj.getString("requestId"));
    }
}
