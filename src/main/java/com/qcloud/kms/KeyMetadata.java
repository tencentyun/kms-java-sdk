package com.qcloud.kms;

/**
 * @
 * @author York.
 * @date 2017-2-20
 */
public class KeyMetadata {
	/*
	 *
	 */

	public String KeyId;
	public int CreateTime;
	public String Description ;
	public String KeyState;
	public String KeyUsage;
	public String Alias ;

    public KeyMetadata()
    {
    	KeyId= "";
    	CreateTime = -1;
    	Description="";
    	KeyState = "";
    	KeyUsage = "";
    	Alias = "";
    }

}
