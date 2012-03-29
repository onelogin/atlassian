package com.onelogin.confluence.saml;

import java.security.Principal;

import com.atlassian.user.User;

public class TestSAML {

	public static void main(String [] args){
		try{
			TestSAML ts = new TestSAML();
			String s = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0"+
						"YzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6"+
						"bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJHT1NBTUxSMTMzMTQz"+
						"NTYwNzU1MDciIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIyMDEyLTAz"+
						"LTExVDAzOjEzOjI3WiIgRGVzdGluYXRpb249IntyZWNpcGllbnR9IiBJblJl"+
						"c3BvbnNlVG89Il8zMzhjNDRkMi0xMTViLTRhZDItYTQyNC0yN2Y1OWUzNzNm"+
						"MWUiPjxzYW1sOklzc3Vlcj5odHRwczovL2FwcC5vbmVsb2dpbi5jb20vc2Ft"+
						"bC9tZXRhZGF0YS8zODYwMDwvc2FtbDpJc3N1ZXI+PHNhbWxwOlN0YXR1cz48"+
						"c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNB"+
						"TUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1scDpTdGF0dXM+PHNhbWw6"+
						"QXNzZXJ0aW9uIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hN"+
						"TFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hN"+
						"TFNjaGVtYS1pbnN0YW5jZSIgVmVyc2lvbj0iMi4wIiBJRD0icGZ4YWYzNjVh"+
						"YTEtNTI1ZS1jMGIxLTlkY2EtZjgwOTFhODMwNWIzIiBJc3N1ZUluc3RhbnQ9"+
						"IjIwMTItMDMtMTFUMDM6MTM6MjdaIj48c2FtbDpJc3N1ZXI+aHR0cHM6Ly9h"+
						"cHAub25lbG9naW4uY29tL3NhbWwvbWV0YWRhdGEvMzg2MDA8L3NhbWw6SXNz"+
						"dWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3Jn"+
						"LzIwMDAvMDkveG1sZHNpZyMiPgogIDxkczpTaWduZWRJbmZvPjxkczpDYW5v"+
						"bmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5v"+
						"cmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICA8ZHM6U2lnbmF0dXJl"+
						"TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94"+
						"bWxkc2lnI3JzYS1zaGExIi8+CiAgPGRzOlJlZmVyZW5jZSBVUkk9IiNwZnhh"+
						"ZjM2NWFhMS01MjVlLWMwYjEtOWRjYS1mODA5MWE4MzA1YjMiPjxkczpUcmFu"+
						"c2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3Lncz"+
						"Lm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxk"+
						"czpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAx"+
						"LzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2Vz"+
						"dE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkv"+
						"eG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPnZpN2RZckN1YTEwWDNN"+
						"WWNLZmh6V2lmVzFVaz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNl"+
						"PjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+d3BKd0llRXlP"+
						"a2tWQmF4USs3dkxKSVVaaHBmNUZMNDZFQThxUDBQZVhxV2FCaWpjeE40U2FP"+
						"Zlg2OU42VW9BbVZPUkF6Q1dCL3N6Mk1NSEJCQ3dyOFhWUGhWdkliZmFuWm11"+
						"bW9XV2o3ZjhMUWlHNDJzcHY2QzlxVTVBOEZNaCt6a29WcFBsUjJDR25NUXRD"+
						"dHJBWEpQYW1QYUhvbDN2MzhPUnZPTk1tUlpjbFE3M0dzUU5Jc2xQa2lQRVY5"+
						"eUNVdFprTGxzSFFmclNzOFV2VW90NWowbU9EZzZoRE1BQ2x4Ympwenhadkdk"+
						"aDdFbjVMQUk0QlhRbnNIcjJlbDVkUkhCWlB0U0Q3OFMyQklNdnA1cGdMQ25x"+
						"TGFaSG01V1pMRzFHVWNHek9hYkNjbFhCRW9VRWs1clh3L3hrYWFkcGwyL0kr"+
						"K2NPZkZTajlIKy9zdTZrRUx3PT08L2RzOlNpZ25hdHVyZVZhbHVlPgo8ZHM6"+
						"S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlD"+
						"TVRDQ0FpV2dBd0lCQWdJQkFUQURCZ0VBTUdjeEN6QUpCZ05WQkFZVEFsVlRN"+
						"Uk13RVFZRFZRUUlEQXBEWVd4cFptOXlibWxoTVJVd0V3WURWUVFIREF4VFlX"+
						"NTBZU0JOYjI1cFkyRXhFVEFQQmdOVkJBb01DRTl1WlV4dloybHVNUmt3RndZ"+
						"RFZRUUREQkJoY0hBdWIyNWxiRzluYVc0dVkyOXRNQjRYRFRFeU1ESXlNREU0"+
						"TkRreE1sb1hEVEUzTURJeE9URTRORGt4TWxvd1p6RUxNQWtHQTFVRUJoTUNW"+
						"Vk14RXpBUkJnTlZCQWdNQ2tOaGJHbG1iM0p1YVdFeEZUQVRCZ05WQkFjTURG"+
						"TmhiblJoSUUxdmJtbGpZVEVSTUE4R0ExVUVDZ3dJVDI1bFRHOW5hVzR4R1RB"+
						"WEJnTlZCQU1NRUdGd2NDNXZibVZzYjJkcGJpNWpiMjB3Z2dFaU1BMEdDU3FH"+
						"U0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRFJYMFJMZDNmRllLRDBB"+
						"aml2RG4xUGZrZUVKTlpJcEJzTUpRQyt1a1NOaTh5eDF1U082dzNTVlZNTzRZ"+
						"LzMvL3JZcXNBbXJBUEc5NWhSQ1VaZmswb08xdDA1VERyM0xONHozQ0EwUkE0"+
						"VXF5Ny9WN2pZWVFINzJ5aU1oZWFZOStSNUkybFlEMTRBTHpTZ3ZlYnZlNG4w"+
						"OURMZitkbm1KZkg2YW55Q3pSWlI0UDVMMHJuQmNsbGJ2ZUMxdmFTWGdGUVJP"+
						"ck9EdmJwRzJGSTcrcUp3b2N1TmpmZlRSWEtNVEdiTit2UXl3Z2c0V3JudWtV"+
						"R2RNV0w4cmIycWxQdWtXTVA2ZnFIVHJnTTV5ZXZmV24wR3M5VmFRdXBlaXVN"+
						"R283ZExuYVVmSkltNm1iY0hDTzVzd3VaUGtKUTJQOXhKS0hCMmM0Qk5pMHE5"+
						"QzhtUGhVZlZtc0xkQWdNQkFBRXdBd1lCQUFNQkFBPT08L2RzOlg1MDlDZXJ0"+
						"aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25h"+
						"dHVyZT48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpv"+
						"YXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRk"+
						"cmVzcyI+Z21hcnJ1Zm9AZ21kc2NvbnN1bHRpbmcuY29tPC9zYW1sOk5hbWVJ"+
						"RD48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lz"+
						"Om5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWw6U3ViamVjdENv"+
						"bmZpcm1hdGlvbkRhdGEgTm90T25PckFmdGVyPSIyMDEyLTAzLTExVDAzOjE4"+
						"OjI3WiIgUmVjaXBpZW50PSJ7cmVjaXBpZW50fSIgSW5SZXNwb25zZVRvPSJf"+
						"MzM4YzQ0ZDItMTE1Yi00YWQyLWE0MjQtMjdmNTllMzczZjFlIi8+PC9zYW1s"+
						"OlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29u"+
						"ZGl0aW9ucyBOb3RCZWZvcmU9IjIwMTItMDMtMTFUMDM6MDg6MjdaIiBOb3RP"+
						"bk9yQWZ0ZXI9IjIwMTItMDMtMTFUMDM6MTg6MjdaIj48c2FtbDpBdWRpZW5j"+
						"ZVJlc3RyaWN0aW9uPjxzYW1sOkF1ZGllbmNlPnthdWRpZW5jZX08L3NhbWw6"+
						"QXVkaWVuY2U+PC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PC9zYW1sOkNv"+
						"bmRpdGlvbnM+PHNhbWw6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIy"+
						"MDEyLTAzLTExVDAzOjEzOjI3WiIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAx"+
						"Mi0wMy0xMlQwMzoxMzoyN1oiIFNlc3Npb25JbmRleD0iXzEzNzU1N2FlYzI2"+
						"ZGZiNjc0MDQwNzUwNzMzZTI0ODgyIj48c2FtbDpBdXRobkNvbnRleHQ+PHNh"+
						"bWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNB"+
						"TUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmRQcm90ZWN0ZWRUcmFuc3BvcnQ8"+
						"L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+PC9zYW1sOkF1dGhuQ29udGV4"+
						"dD48L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+PC9zYW1sOkFzc2VydGlvbj48L3Nh"+
						"bWxwOlJlc3BvbnNlPgoK";
			ts.validateSAML(s);
		}
		catch(Exception e){
		}
	}

	public void validateSAML(String s)
	{
		try{
			String certificateS = "MIICMTCCAiWgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApD"+
					"YWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxv"+
					"Z2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEyMDIyMDE4NDkxMloX"+
					"DTE3MDIxOTE4NDkxMlowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3Ju"+
					"aWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAX"+
					"BgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw"+
					"ggEKAoIBAQDRX0RLd3fFYKD0AjivDn1PfkeEJNZIpBsMJQC+ukSNi8yx1uSO6w3S"+
					"VVMO4Y/3//rYqsAmrAPG95hRCUZfk0oO1t05TDr3LN4z3CA0RA4Uqy7/V7jYYQH7"+
					"2yiMheaY9+R5I2lYD14ALzSgvebve4n09DLf+dnmJfH6anyCzRZR4P5L0rnBcllb"+
					"veC1vaSXgFQROrODvbpG2FI7+qJwocuNjffTRXKMTGbN+vQywgg4WrnukUGdMWL8"+
					"rb2qlPukWMP6fqHTrgM5yevfWn0Gs9VaQupeiuMGo7dLnaUfJIm6mbcHCO5swuZP"+
					"kJQ2P9xJKHB2c4BNi0q9C8mPhUfVmsLdAgMBAAEwAwYBAAMBAA==";

			AccountSettings accountSettings = new AccountSettings();
			accountSettings.setCertificate(certificateS);

			Response samlResponse = new Response(accountSettings);
			samlResponse.loadXmlFromBase64(s);

			if (samlResponse.isValid())
			{
				final String nameId = samlResponse.getNameId();
				System.out.println(nameId);
				
				Principal user = null;
				
				user = new User() {
					public String getFullName() {
						return "admin";
					}

					public String getEmail() {
						return nameId;
					}

					public String getName() {
						return "admin";
					}
				};
				
				System.out.println("stop for a minute");
				
				
				
			}
			else
			{
			}
		}
		catch(Exception e){
			System.out.println(e.getMessage());
		}
	}
}
