package com.ISOServer;

import java.io.*;
import java.util.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public class Library
{
	
	static SecretKey key_3des;

	static byte[] generarPinBlock(String pin, String tarjeta)
	{
		byte[] p1 = new byte[8];
		byte[] p2 = new byte[8];
		byte[] res = new byte[8];
		
		try
		{
			leerLlave();
		
			if (key_3des != null && pin.length() == 4 && tarjeta.length() == 19)
			{
				p1[0] = (byte) 0x04;
				p1[1] = (byte) Integer.parseInt(pin.substring(0,2), 16);
				p1[2] = (byte) Integer.parseInt(pin.substring(2,4), 16);
				p1[3] = (byte) 0xFF;
				p1[4] = (byte) 0xFF;
				p1[5] = (byte) 0xFF;
				p1[6] = (byte) 0xFF;
				p1[7] = (byte) 0xFF;
					
				p2[0] = (byte) 0x00;
				p2[1] = (byte) 0x00;
				p2[2] = (byte) Integer.parseInt(tarjeta.substring(6,8), 16);
				p2[3] = (byte) Integer.parseInt(tarjeta.substring(8,10), 16);
				p2[4] = (byte) Integer.parseInt(tarjeta.substring(10,12), 16);
				p2[5] = (byte) Integer.parseInt(tarjeta.substring(12,14), 16);
				p2[6] = (byte) Integer.parseInt(tarjeta.substring(14,16), 16);
				p2[7] = (byte) Integer.parseInt(tarjeta.substring(16,18), 16);
					
				res[0] = (byte) (p1[0] ^ p2[0]);
				res[1] = (byte) (p1[1] ^ p2[1]);
				res[2] = (byte) (p1[2] ^ p2[2]);
				res[3] = (byte) (p1[3] ^ p2[3]);
				res[4] = (byte) (p1[4] ^ p2[4]);
				res[5] = (byte) (p1[5] ^ p2[5]);
				res[6] = (byte) (p1[6] ^ p2[6]);
				res[7] = (byte) (p1[7] ^ p2[7]);
			
				return encrypt3DES(key_3des, res);
			}
			else
			{
				return null;
			}
		}
		catch (Exception e)
		{
			return null;
		}
	}

	static byte[] encrypt3DES(SecretKey llave, byte[] texto) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException
	{
		byte[] buffer_res = new byte[8];
		
		try
		{
			Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, llave);
			buffer_res = cipher.doFinal(texto);
		}
		catch (Exception e)
		{
			System.out.println(e);
		}
		
		return buffer_res;
	}
	
	static void leerLlave() throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException 
	{
		byte[] desKeyData = new byte[24];
		FileReader input = new FileReader("llave.3des");
		BufferedReader bufRead = new BufferedReader(input);
		String line;
		
		try
		{
			line = bufRead.readLine();
			
			if (line.length() != 48)
			{
				key_3des = null;
			}
			else
			{
				for (int i = 0; i < 24; i++)
				{
					desKeyData[i] = (byte) Integer.parseInt(line.substring(i*2,(i*2) + 2), 16);
				}
			}
			
			DESedeKeySpec keyspec = new DESedeKeySpec(desKeyData);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
			SecretKey key_g = keyFactory.generateSecret(keyspec);
			key_3des = key_g;
		}
		catch (Exception e)
		{
			key_3des = null;
		}
		
	}
	
	static String byteArrayToHexString(byte in[]) 
	{
		byte ch = 0x00;
		int i = 0; 
		if (in == null || in.length <= 0)
			return null;
		
		String pseudo[] = {"0", "1", "2","3", "4", "5", "6", "7", "8","9", "A", "B", "C", "D", "E","F"};
		StringBuffer out = new StringBuffer(in.length * 2);
		
		while (i < in.length) 
		{
			ch = (byte) (in[i] & 0xF0); // Strip off high nibble
			ch = (byte) (ch >>> 4); // shift the bits down
			ch = (byte) (ch & 0x0F); // must do this is high order bit is on!
			out.append(pseudo[ (int) ch]); // convert the nibble to a String Character
			ch = (byte) (in[i] & 0x0F); // Strip off low nibble 
			out.append(pseudo[ (int) ch]); // convert the nibble to a String Character
			i++;
		}
		
		String rslt = new String(out);
		return rslt;
	}
	
	/**
	 * 	
	 * @param tipo_mensaje: Este método se encarga de evaluar el tipo de transacción que se desea ejecuta  realizando la comparación con el código de proceso correspondiente.
	 * @param codigo_proceso: Se encarga de Evaluar el código de proceso en mase al tipo de mesaje empleado, es decir si se desea consultar el saldo de una tarjeta de crédito el valor seria tipo_mensaje.equals("0200") && (codigo_proceso.equals("303000")
	 */
	
	public static byte[] bitmapISO8583(String tipo_mensaje, String codigo_proceso)
	{
	
		byte[] respuesta = new byte[8];
		
		// Mensaje Login
		if (tipo_mensaje.equals("0800") && codigo_proceso.equals("920000"))
		{
			respuesta[0] = (byte) 0x0020;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0001;
			respuesta[3] = (byte) 0x0000;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x0080;
			respuesta[6] = (byte) 0x0000;
			respuesta[7] = (byte) 0x0000;
		}
		// Mensaje Login Resp
		else if (tipo_mensaje.equals("0810") && codigo_proceso.equals("920000"))
		{
			respuesta[0] = (byte) 0x0020;
			respuesta[1] = (byte) 0x0038;
			respuesta[2] = (byte) 0x0001;
			respuesta[3] = (byte) 0x0000;
			respuesta[4] = (byte) 0x0002;
			respuesta[5] = (byte) 0x0080;
			respuesta[6] = (byte) 0x0000;
			respuesta[7] = (byte) 0x0004;
		}
		// Mensaje Test
		else if (tipo_mensaje.equals("0800") && codigo_proceso.equals("990000"))
		{
			respuesta[0] = (byte) 0x0020;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0001;
			respuesta[3] = (byte) 0x0000;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x0080;
			respuesta[6] = (byte) 0x0000;
			respuesta[7] = (byte) 0x0000;
		}
		// Mensaje Test Resp
		else if (tipo_mensaje.equals("0810") && codigo_proceso.equals("990000"))
		{
			respuesta[0] = (byte) 0x0020;
			respuesta[1] = (byte) 0x0038;
			respuesta[2] = (byte) 0x0001;
			respuesta[3] = (byte) 0x0000;
			respuesta[4] = (byte) 0x0002;
			respuesta[5] = (byte) 0x0080;
			respuesta[6] = (byte) 0x0000;
			respuesta[7] = (byte) 0x0000;
		}
		// Mensaje Consulta Cuentas -->>Fidecomiso 06/02/2014
		
		else if (tipo_mensaje.equals("0200") && (codigo_proceso.equals("301000") || codigo_proceso.equals("302000")|| codigo_proceso.equals("354000")))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C0;
			respuesta[6] = (byte) 0x0010;
			respuesta[7] = (byte) 0x0000;
		}
		
		
		// Mensaje Consulta Saldo TDC Modificado Miguel Uzcategui 17/01/2014
		// Se agrega la consulta de cadivi 11/02/2014 Miguel Uzcategui codigo_proceso.equals("303000")||
		else if (tipo_mensaje.equals("0200") && ( codigo_proceso.equals("364000")|| codigo_proceso.equals("344000")|| codigo_proceso.equals("346000")|| codigo_proceso.equals("303100")))
			{
					respuesta[0] = (byte) 0x0070;
					respuesta[1] = (byte) 0x0020;
					respuesta[2] = (byte) 0x0045;
					respuesta[3] = (byte) 0x0080;
					respuesta[4] = (byte) 0x0000;
					respuesta[5] = (byte) 0x00C0;
					respuesta[6] = (byte) 0x0000;
					respuesta[7] = (byte) 0x0000;
		
						}
		
		// Mensaje Consulta Movimientos //modificado Miguel Uzcategui
		else if (tipo_mensaje.equals("0200") && (codigo_proceso.equals("321000") || codigo_proceso.equals("322000") || codigo_proceso.equals("323000") || codigo_proceso.equals("311000") || codigo_proceso.equals("312000")))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C0;
			respuesta[6] = (byte) 0x0010;
			respuesta[7] = (byte) 0x0000;
		}
		// Mensaje Consulta SALDO TDC //modificado Miguel Uzcategui
		else if ( tipo_mensaje.equals("0200") && codigo_proceso.equals("303000"))
				{
					respuesta[0] = (byte) 0x0070;
					respuesta[1] = (byte) 0x0020;
					respuesta[2] = (byte) 0x0045;
					respuesta[3] = (byte) 0x0080;
					respuesta[4] = (byte) 0x0000;
					respuesta[5] = (byte) 0x00d0;
					respuesta[6] = (byte) 0x0010;
					respuesta[7] = (byte) 0x0000;
				}
		
		// Mensaje Transferencias Propias
		else if (tipo_mensaje.equals("0200") && (codigo_proceso.equals("401020") || codigo_proceso.equals("402010")))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C0;
			respuesta[6] = (byte) 0x0010;
			respuesta[7] = (byte) 0x0000;
		}
		// Mensaje Transferencias Terceros (Mismo Banco)
		else if (tipo_mensaje.equals("0200") && (codigo_proceso.equals("481010") || codigo_proceso.equals("481020") || codigo_proceso.equals("482010") || codigo_proceso.equals("482020")))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C0;
			respuesta[6] = (byte) 0x0010;
			respuesta[7] = (byte) 0x0010;
		}
		// Mensaje Creacion PIN
		else if (tipo_mensaje.equals("0200") && codigo_proceso.equals("940000"))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C1;
			respuesta[6] = (byte) 0x0018;
			respuesta[7] = (byte) 0x0000;
		}
		// Mensaje Cambio PIN
		else if (tipo_mensaje.equals("0200") && codigo_proceso.equals("950000"))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C1;
			respuesta[6] = (byte) 0x0018;
			respuesta[7] = (byte) 0x0000;
		}
		// Mensaje Bloqueo Cliente
		else if (tipo_mensaje.equals("0200") && codigo_proceso.equals("960000"))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C1;
			respuesta[6] = (byte) 0x0000;
			respuesta[7] = (byte) 0x0000;
		}		
		// Mensaje Asignacion PIN
		else if (tipo_mensaje.equals("0200") && codigo_proceso.equals("940001"))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C1;
			respuesta[6] = (byte) 0x0010;
			respuesta[7] = (byte) 0x0000;
		}		
		// Mensaje Pago Servicios
		else if (tipo_mensaje.equals("0200") && (codigo_proceso.equals("501000") || codigo_proceso.equals("502000")))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C0;
			respuesta[6] = (byte) 0x0010;
			respuesta[7] = (byte) 0x0014;
		}
		// Mensaje Conformacion Cheque
		else if (tipo_mensaje.equals("0100") && codigo_proceso.equals("032000"))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C0;
			respuesta[6] = (byte) 0x0000;
			respuesta[7] = (byte) 0x0002;
		}
		// Mensaje Reverso TimeOut
		else if (tipo_mensaje.equals("0400") && (codigo_proceso.equals("501000") || codigo_proceso.equals("502000") || codigo_proceso.equals("501000")))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C0;
			respuesta[6] = (byte) 0x0000;
			respuesta[7] = (byte) 0x0002;
		}
		// Mensaje Consulta Datos Cliente
		else if (tipo_mensaje.equals("0200") && codigo_proceso.equals("970000"))
		{
			respuesta[0] = (byte) 0x0070;
			respuesta[1] = (byte) 0x0020;
			respuesta[2] = (byte) 0x0045;
			respuesta[3] = (byte) 0x0080;
			respuesta[4] = (byte) 0x0000;
			respuesta[5] = (byte) 0x00C1;
			respuesta[6] = (byte) 0x0000;
			respuesta[7] = (byte) 0x0000;
		}

		return respuesta;
	}

	/**
	 * 
	 * @param arreglo: Se encarga de evaluar que campo esta activo en el mesaje 0210 segun la consuta solicitada.
	 *
	 */

	public static boolean validaBitmapISO8583(byte[] arreglo, String tipo_mensaje, String codigo_proceso)
	{
		String campos_prendidos = "";
		boolean igual = false;
		
		// Mensaje Login Respuesta
		if (tipo_mensaje.equals("0810") && codigo_proceso.equals("920000"))
		{
			if (Library.camposPrendidos(arreglo).equals("3-11-12-13-24-39-41-62"))
				igual = true;
		}
		// Mensaje Test Respuesta
		else if (tipo_mensaje.equals("0810") && codigo_proceso.equals("990000"))
		{
			if (Library.camposPrendidos(arreglo).equals("3-11-12-13-24-39-41"))
				igual = true;
		}
		// Mensaje Consulta Cuentas Respuesta fidecomiso tambien 06/02/2014
		else if (tipo_mensaje.equals("0210") && (codigo_proceso.equals("301000") || codigo_proceso.equals("302000") || codigo_proceso.equals("354000")|| codigo_proceso.equals("344000") || codigo_proceso.equals("346000")))
		{
			if (Library.camposPrendidos(arreglo).equals("2-3-11-12-13-24-37-39-41-43-54"))
				igual = true;
		} 
		
		// Mensaje Consulta Saldo TDC Respuesta Modificado por Miguel Uzcategui 17/01/2014
		// SE AGREGA LA CONSULTA DE CUPO CADIVI 11/02/2014 Miguel Uzcategui
		else if (tipo_mensaje.equals("0210") && (codigo_proceso.equals("303000") || codigo_proceso.equals("364000")|| codigo_proceso.equals("303100")))
				{
			if (Library.camposPrendidos(arreglo).equals("2-3-11-12-13-24-37-39-41-43-54"))
			igual = true;
			
				} 
		
		// Mensaje Consulta Movimientos Respuesta //Modificado Miguel Uzcategui
		else if (tipo_mensaje.equals("0210") && (codigo_proceso.equals("321000") || codigo_proceso.equals("322000") || codigo_proceso.equals("323000") || codigo_proceso.equals("311000") || codigo_proceso.equals("312000")))
		{
			if (Library.camposPrendidos(arreglo).equals("2-3-11-12-13-24-37-39-41-54-60"))
				igual = true;
		}
		// Mensaje Transferencias Propias Respuesta
		else if (tipo_mensaje.equals("0210") && (codigo_proceso.equals("401020") || codigo_proceso.equals("402010")))
		{
			if (Library.camposPrendidos(arreglo).equals("2-3-11-12-13-24-37-39-41-54-60"))
				igual = true;
		}
		// Mensaje Transferencias Terceros (Mismo Banco) Respuesta
		else if (tipo_mensaje.equals("0210") && (codigo_proceso.equals("481010") || codigo_proceso.equals("481020") || codigo_proceso.equals("482010") || codigo_proceso.equals("482020")))
		{
			if (Library.camposPrendidos(arreglo).equals("2-3-11-12-13-24-37-39-41-54-60"))
				igual = true;
		}
		// Mensaje Asignacion / Cambio PIN Respuesta
		else if (tipo_mensaje.equals("0210") && codigo_proceso.equals("940000"))
		{
			if (Library.camposPrendidos(arreglo).equals("2-3-11-12-13-24-37-39-41"))
				igual = true;
		}
		// Mensaje Pago Servicios Respuesta
		else if (tipo_mensaje.equals("0210") && (codigo_proceso.equals("501000") || codigo_proceso.equals("502000")))
		{
			if (Library.camposPrendidos(arreglo).equals("2-3-11-12-13-24-37-39-41"))
				igual = true;
		}
		// Mensaje Conformacion Cheque Respuesta
		else if (tipo_mensaje.equals("0110") && codigo_proceso.equals("032000"))
		{
			if (Library.camposPrendidos(arreglo).equals("2-3-11-12-13-24-37-39-41"))
				igual = true;
		}
		
		return igual;
	}
	
	
	public static byte[] ISO8583msgLogin(long SystemTraceNumber, String NetworkIDNumber, String TerminalID)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0800");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0800", "920000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("920000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
	
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	
	public static byte[] ISO8583msgTest(long SystemTraceNumber, String NetworkIDNumber, String TerminalID)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0800");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0800", "990000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("990000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
			
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	
	public static byte[] ISO8583msgLoginResp(long SystemTraceNumber, String NetworkIDNumber, String TerminalID)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0810");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0810", "920000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("920000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("061181");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("9999");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
			
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	
	public static byte[] ISO8583msgTestResp(long SystemTraceNumber, String NetworkIDNumber, String TerminalID)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0810");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0810", "990000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("990000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("061181");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("9999");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
			
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	/**
	 * 
	 * @param SystemTraceNumber: Representa el numero correspondiente al a la traza del sistema.
	 * @param NetworkIDNumber: Indica el numero de la ID de red.
	 * @param TerminalID: Corresponde a la Id del terminal.
	 * @param TipoConsulta: Señala el tipo de consulta a realizar, es decir emplea el codigo de proceso que corresponde a la transaccion.
	 * @param TarjetaDebito: Hace referencia a la tarjeta de debito correspondiente a la cuenta que se le realiza la consulta.
	 * @param PIN: Identifica la clave correspondiente a la tarjeta de debito del usuario.
	 */
	//consulta de fidecomiso
	public static byte[] ISO8583msgConsultaSaldo(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TipoConsulta, String TarjetaDebito, String PIN)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", TipoConsulta);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TipoConsulta);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = generarPinBlock(PIN, TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
			
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	/**
	 * 
	 * @param SystemTraceNumber: Representa el numero correspondiente al a la traza del sistema.
	 * @param NetworkIDNumber: Indica el numero de la ID de red.
	 * @param TerminalID: Corresponde a la Id del terminal.
	 * @param TipoConsulta: Señala el tipo de consulta a realizar, es decir emplea el codigo de proceso que corresponde a la transaccion.
	 * @param TarjetaDebito: Hace referencia a la cuenta que se le realiza la consulta sobre el cupo cadivi correspondiente.
	 * 
	 */
	//modificado para cadivi 13/03/2014
		public static byte[] ISO8583msgConsultaCadivi(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TipoConsulta, String TarjetaDebito)
		{
			byte[] respuesta = new byte[0];
			byte[] lectura;
			Merger union;
			
			lectura = BCDConversor.string2BCD("0200");
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = bitmapISO8583("0200", TipoConsulta);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(TipoConsulta);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD("011");
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(NetworkIDNumber);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD("00");
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(TerminalID);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(CardAcqID);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			//lectura = generarPinBlock(PIN, TarjetaDebito);
		//	union = new Merger(respuesta, lectura);
	//		respuesta = union.getArray();
				
			lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
			union = new Merger(lectura, respuesta);
			respuesta = union.getArray();
			
			return respuesta;	
		}	
	
	//////////////////////////////////////////////////////////////////////////////////////////
	////////MODIFICADO POR Miguel Uzcategui/////////////////////////////////////////////////////
	
	/*
		public static byte[] ISO8583msgConsultaSaldoTDC(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TipoConsulta, String TarjetaCredito,String TarjetaDebito)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", TipoConsulta);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		
		//modificado por Miguel Uzcategui OLTP ajuste de longitud TDC a 16 bits
		//lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		lectura = BCDConversor.string2BCD(TarjetaCredito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TipoConsulta);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();		
		
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	*/
//////////////////////////////////////////////////////////////////////////////////////////
////////MODIFICADO POR MIGUEL UZCATEGUI/////////////////////////////////////////////////////
	/**
	 * 
	 * @param SystemTraceNumber: Representa el numero correspondiente al a la traza del sistema.
	 * @param NetworkIDNumber: Indica el numero de la ID de red.
	 * @param TerminalID: Corresponde a la Id del terminal.
	 * @param TipoConsulta: Señala el tipo de consulta a realizar, es decir emplea el codigo de proceso que corresponde a la transaccion.
	 * @param TarjetaDebito: Se emplea para validar que el cliente que desea confirmar su referencia bancaria es cliente.
	 */
	public static byte[] ISO8583msgConsultaReferencia(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TipoConsulta, String TarjetaDebito)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", TipoConsulta);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TipoConsulta);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();

		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	
///ISO8583IdentificacionPositiva/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	public static byte[] ISO8583msgIdentificacionPositiva(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TipoConsulta, String TarjetaDebito)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", TipoConsulta);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TipoConsulta);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();

		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	/**
	 * 
	 * @param SystemTraceNumber: Representa el numero correspondiente al a la traza del sistema.
	 * @param NetworkIDNumber: Indica el numero de la ID de red.
	 * @param TerminalID: Corresponde a la Id del terminal.
	 * @param TipoConsulta: Señala el tipo de consulta a realizar, es decir emplea el codigo de proceso que corresponde a la transaccion.
	 * @param TarjetaDebito: Hace referencia a la cuenta que se le realiza la consulta sobre los ultimos movimientos correspondientes.
	 * @param PIN: Identifica la clave correspondiente a la tarjeta de debito del usuario.
	 */
	public static byte[] ISO8583msgConsultaMovimientos(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TipoConsulta, String TarjetaDebito, String PIN)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", TipoConsulta);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TipoConsulta);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = generarPinBlock(PIN, TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
			
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	//METODO DE PRUEBA PARA NUEVA CONSULTA TDC\\ MIGUEL UZCATEGUI 15/04/2014
	/**
	 * @param SystemTraceNumber: Representa el numero correspondiente al a la traza del sistema.
	 * @param NetworkIDNumber: Indica el numero de la ID de red.
	 * @param TerminalID: Corresponde a la Id del terminal.
	 * @param TipoConsulta: Señala el tipo de consulta a realizar, es decir emplea el codigo de proceso que corresponde a la transaccion.
	 * @param TarjetaCredito: Es el numero de tarjeta de credito en base a la que se hara la consulta de su saldo. 
	 * @param TarjetaDebito: Hace referencia a la tarjeta de debito con la que se valida la existencia de la tarjeta de credito.
	 * @param PIN: Identifica la clave correspondiente a la tarjeta de debito del usuario.
	 * 
	 */
	public static byte[] ISO8583msgConsultaNewTDC(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TarjetaCredito, String TipoConsulta, String TarjetaDebito, String PIN)
		{
			byte[] respuesta = new byte[0];
			byte[] lectura;
			Merger union;
			
			lectura = BCDConversor.string2BCD("0200");
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = bitmapISO8583("0200", TipoConsulta);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(TipoConsulta);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD("011");
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(NetworkIDNumber);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD("00");
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(TerminalID);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(CardAcqID);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = BCDConversor.string2BCD(TarjetaCredito);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
			
			lectura = generarPinBlock(PIN, TarjetaDebito);
			union = new Merger(respuesta, lectura);
			respuesta = union.getArray();
				
			lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
			union = new Merger(lectura, respuesta);
			respuesta = union.getArray();
			
			return respuesta;	
		}
	public static byte[] ISO8583msgTransferenciasPropias(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TipoTransferencia, String TarjetaDebito, String PIN, String MontoTransferir)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", TipoTransferencia);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TipoTransferencia);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(MontoTransferir, 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = generarPinBlock(PIN, TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
			
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	public static byte[] ISO8583msgTransferenciasTerceros(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TipoTransferencia, String TarjetaDebito, String PIN, String CuentaTransferir, String MontoTransferir)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", TipoTransferencia);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TipoTransferencia);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(MontoTransferir, 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = generarPinBlock(PIN, TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(CuentaTransferir.length()),3) + CuentaTransferir);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
			
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}

	public static byte[] ISO8583msgCambioPIN(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TarjetaDebito, String PIN, String PINNUEVO, String Cedula)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", "950000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("950000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("010" + CompletoCerosIzquierda(Cedula,10));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = generarPinBlock(PIN, TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = generarPinBlock(PINNUEVO, TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}

	public static byte[] ISO8583msgAsignacionPIN(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TarjetaDebito, String PIN, String Cedula)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", "940001");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("940000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("010" + CompletoCerosIzquierda(Cedula,10));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = generarPinBlock(PIN, TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}

	public static byte[] ISO8583msgPagoServicios(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TipoPagoServicio, String TarjetaDebito, String PIN, String CuentaPago, String MontoPago, String Servicio)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", TipoPagoServicio);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TipoPagoServicio);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(MontoPago, 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = generarPinBlock(PIN, TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(CuentaPago.length()),3) + CuentaPago);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
			
		lectura = BCDConversor.string2BCD(mensajeServicio(Servicio));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();

		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}

	public static byte[] ISO8583msgConformacionCheque(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String NumeroCheque, String NumeroCuenta, String Monto, String CedulaRifPasaporte, String NumCedulaRifPasaporte)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0100");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0100", "032000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(19),2) + "6394890000000000000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("032000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Monto, 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(mensajeAutorizacionCheque(NumeroCheque, NumeroCuenta, Monto, CedulaRifPasaporte, NumCedulaRifPasaporte));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
			
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	
	public static byte[] ISO8583msgConsultaDatosCliente(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TarjetaDebito, String Cedula)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", "970000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("970000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("010" + CompletoCerosIzquierda(Cedula,10));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}
	
	public static byte[] ISO8583msgBloqueoCliente(long SystemTraceNumber, String NetworkIDNumber, String TerminalID, String CardAcqID, String TarjetaDebito, String Cedula)
	{
		byte[] respuesta = new byte[0];
		byte[] lectura;
		Merger union;
		
		lectura = BCDConversor.string2BCD("0200");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = bitmapISO8583("0200", "960000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(TarjetaDebito.length()),2) + TarjetaDebito);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("960000");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 12));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda(Long.toString(SystemTraceNumber),6));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CompletoCerosIzquierda("", 4));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("011");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(NetworkIDNumber);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("00");
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(TerminalID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD(CardAcqID);
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2BCD("010" + CompletoCerosIzquierda(Cedula,10));
		union = new Merger(respuesta, lectura);
		respuesta = union.getArray();
		
		lectura = BCDConversor.string2ASCII(CompletoCerosIzquierda(Long.toString(respuesta.length),4));
		union = new Merger(lectura, respuesta);
		respuesta = union.getArray();
		
		return respuesta;	
	}


	public static void logTraza(byte[] traza, String ente, PrintStream log, int Verbose, int pos)
	{
		String codigo_proceso;
		String codigo_proceso4;
		String tipo_mensaje;
		
		
		String tamano = new String(obtenerCampoArreglo(traza, pos, 4));
		
		escribirLog("|" + ente + "|TAMANO: <" + (tamano) + ">", log, Verbose);
		pos+=4;
		
		byte[] mens = obtenerCampoArreglo(traza, pos, Integer.valueOf(tamano));
		
		tipo_mensaje = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)));
		pos+=4;
		escribirLog("|" + ente + "|TIPO MENSAJE: <" + tipo_mensaje + ">", log, Verbose);
		
		//String flag128 = Library.obtenerCampoArreglo(traza, pos, 2);
			
		String campos_prendidos = Library.camposPrendidos(Library.obtenerCampoArreglo(traza, pos, 8));
		pos+=8;
		
		if(campos_prendidos.charAt(0) == '1')
		{
			pos-= 8;
			campos_prendidos = Library.camposPrendidos16(Library.obtenerCampoArreglo(traza, pos, 16));
			pos+=16; //BITMAP + BITMAP EXTENDIDO
			pos+=19; //TARJETA
			pos+=2;
		}
		
		escribirLog("|" + ente + "|BITMAP: <" + campos_prendidos + ">", log, Verbose);
		
		//Mensajes 0800 Request
		if (tipo_mensaje.equals("0800"))
		{
			codigo_proceso = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)));
			pos+=6;
			escribirLog("|" + ente + "|CODIGO PROCESO: <" + codigo_proceso + ">", log, Verbose);
					
			//Mensaje de Login
			if (codigo_proceso.equals("920000"))
			{
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
			}
			//Mensaje de Test
			else if (codigo_proceso.equals("990000"))
			{
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
			}
		}
		//Mensajes 0810 Response
		else if (tipo_mensaje.equals("0810"))
		{
			codigo_proceso = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)));
			pos+=6;
			escribirLog("|" + ente + "|CODIGO PROCESO: <" + codigo_proceso + ">", log, Verbose);
			
			//Mensaje de Login
			if (codigo_proceso.equals("920000"))
			{
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				
			}
			//Mensaje de Test
			else if (codigo_proceso.equals("990000"))
			{
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
			}	
		}
		//Mensajes 0200 Request
		else if (tipo_mensaje.equals("0200"))
		{
			String codigo_proceso2;
			String codigo_proceso3;
			
			escribirLog("|" + ente + "|RUTINA STANDAR PARA 0200|:", log, Verbose);			
			escribirLog("|POS|:"+pos, log, Verbose);
			int long_cuenta = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2))));
			escribirLog("|" + ente + "|LONG CUENTA PRIMARIA: <" + long_cuenta + ">", log, Verbose);
			pos+=2;
			escribirLog("|" + ente + "|CUENTA PRIMARIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, long_cuenta)))) + ">", log, Verbose);
			pos+=long_cuenta;
			escribirLog("|POS 2|:"+pos, log, Verbose);
			codigo_proceso = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)));
			escribirLog("|" + ente + "|POS DEL CODIGO PROCESO: <" + pos + ">", log, Verbose);
			pos+=6;
			escribirLog("|" + ente + "|CODIGO PROCESO: <" + codigo_proceso + ">", log, Verbose);
			
			
			
			codigo_proceso2 = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 37 , 6)));
			
			codigo_proceso3 = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza,55 , 6)));
			
			//Mensaje de Consulta Saldo --> modificado por Miguel Uzcategui 23/12/2013
			
			if (codigo_proceso.equals("301000") || codigo_proceso.equals("302000") ||  codigo_proceso.equals("354000"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
				pos+=15;
				//escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				//pos+=8;
			}
			
			if (codigo_proceso.equals("303000")) //Ajuste a Estructura de la rafaga en base a la suma de un nuevo campo el 44
			{
				pos+=18;
				//escribirLog("|" + ente + "|CODIGO PROCESO: <" + codigo_proceso3 + ">", log, Verbose);
				pos+=35;
				int long_cuenta2=Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 96, 2))));
				escribirLog("|" + ente + "|LONG CUENTA TDC: <" + long_cuenta2 + ">", log, Verbose);
				pos-=35;
				
				//escribirLog("|POS Para 303000:61|:"+pos, log, Verbose);	
				pos -=18;
				escribirLog("|" + ente + "|MONTO TRANSACCION F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 43, 12)))) + ">", log, Verbose);
				pos+=15;
				escribirLog("|" + ente + "|NUMERO TRAZA F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 55, 6)))) + ">", log, Verbose);
				
				escribirLog("|" + ente + "|TIPO MERCANTE F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 61, 4)))) + ">", log, Verbose);
				pos+=10;
				escribirLog("|" + ente + "|TIPO ENTRADA POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 65, 3)))) + ">", log, Verbose);
				pos-=1;
				escribirLog("|" + ente + "|ID RED F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 68, 3)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|CODIGO CONDICION POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza,71, 2)))) + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 73, 8)))) + ">", log, Verbose);
				pos+=10;
				escribirLog("|" + ente + "|ID CARD ACQ F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 81, 15)))) + ">", log, Verbose);
				pos+=17;
				escribirLog("|" + ente + "|LONG CUENTA TDC: <" + long_cuenta2 + ">", log, Verbose);
				escribirLog("|" + ente + "|Tarjeta TDC: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 98, long_cuenta2)))) + ">", log, Verbose);
				
				//pos+=15;
								//escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				//pos+=8;
			}
			
			else if ( codigo_proceso2.equals("346000")|| codigo_proceso2.equals("344000"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 41, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 53, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 59, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 63, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 66, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 69, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 71, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 79, 15)))) + ">", log, Verbose);
				pos+=15;
				//escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				//pos+=8;
			}
			//Consulta de referencia bancaria
			else if ( codigo_proceso.equals("364000")) 
				
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 41, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 54, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 60, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 64, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 67, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 70, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 72, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 80, 15)))) + ">", log, Verbose);
				pos+=15;
				//escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				//pos+=8;
			}
			//solo tdcde referencia bancaria
			else if ( codigo_proceso.equals("303100")) 
				
			{
				
				escribirLog("|" + ente + "|MONTO TRANSACCION F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 33, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 45, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 51, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 55, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 58, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 61, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 63, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 71, 15)))) + ">", log, Verbose);
				pos+=15;
				//escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				//pos+=8;
			}
			//RAFAGA MENSAJE 0200 IDENTIFICACION POSITIVA MIGUEL UZCATEGUI 23/09/2014
			else if ( codigo_proceso.equals("303100")) 
				
			{
				
				escribirLog("|" + ente + "|MONTO TRANSACCION F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 33, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 45, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 51, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 55, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 58, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 61, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 63, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ F: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 71, 15)))) + ">", log, Verbose);
				pos+=15;
				//escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				//pos+=8;
			}
			else if (codigo_proceso.equals("321000") || codigo_proceso.equals("322000") || codigo_proceso.equals("323000"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
				pos+=15;
				escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				pos+=8;
			}
			else if (codigo_proceso.equals("401020") || codigo_proceso.equals("402010"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
				pos+=15;
				escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				pos+=8;
			}
			else if (codigo_proceso.equals("481010") || codigo_proceso.equals("481020") || codigo_proceso.equals("482010") || codigo_proceso.equals("482020"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
				pos+=15;
				escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				pos+=8;
				int long_datos = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
				pos+=3;
				escribirLog("|" + ente + "|LONG DATOS: <" + long_datos + ">", log, Verbose);
				escribirLog("|" + ente + "|CUENTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, long_datos)))) + ">", log, Verbose);
				pos+=long_datos;
			}
			else if (codigo_proceso.equals("501000") || codigo_proceso.equals("502000"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
				pos+=15;
				escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				pos+=8;
				int long_datos = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
				pos+=3;
				escribirLog("|" + ente + "|LONG DATOS: <" + long_datos + ">", log, Verbose);
				escribirLog("|" + ente + "|CUENTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, long_datos)))) + ">", log, Verbose);
				pos+=long_datos;
				int long_datos2 = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
				pos+=3;
				escribirLog("|" + ente + "|LONG DATOS: <" + long_datos2 + ">", log, Verbose);
				escribirLog("|" + ente + "|CODIGO SERV: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);	
				pos+=4;
				escribirLog("|" + ente + "|DESC SERV: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 30)))) + ">", log, Verbose);
				pos+=30;
			}
			else if (codigo_proceso.equals("940000"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
				pos+=15;
				int long_datos = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
				pos+=3;
				escribirLog("|" + ente + "|LONG DATOS: <" + long_datos + ">", log, Verbose);
				//escribirLog("|" + ente + "|CVC2: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				//pos+=3;
				escribirLog("|" + ente + "|CEDULA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 10)))) + ">", log, Verbose);
				pos+=10;
				if (campos_prendidos.indexOf("52") != -1)
				{
					escribirLog("|" + ente + "|PIN: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
					pos+=8;
				}
				//escribirLog("|" + ente + "|PINNUEVO: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				//pos+=8;
			}
			else if (codigo_proceso.equals("950000"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
				pos+=15;
				int long_datos = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
				pos+=3;
				escribirLog("|" + ente + "|LONG DATOS: <" + long_datos + ">", log, Verbose);
				//escribirLog("|" + ente + "|CVC2: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				//pos+=3;
				escribirLog("|" + ente + "|CEDULA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 10)))) + ">", log, Verbose);
				pos+=10;
				if (campos_prendidos.indexOf("52") != -1)
				{
					escribirLog("|" + ente + "|PINVIEJO: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
					pos+=8;
				}
				escribirLog("|" + ente + "|PINNUEVO: <" + (new String(Library.obtenerCampoArreglo(traza, pos, 8))) + ">", log, Verbose);
				pos+=8;
			}
			else if (codigo_proceso.equals("960000"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
				pos+=15;
				int long_datos = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
				pos+=3;
				escribirLog("|" + ente + "|LONG DATOS: <" + long_datos + ">", log, Verbose);
				escribirLog("|" + ente + "|CEDULA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 10)))) + ">", log, Verbose);
				pos+=10;
			}
			else if (codigo_proceso.equals("970000"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
				pos+=15;
				int long_datos = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
				pos+=3;
				escribirLog("|" + ente + "|LONG DATOS: <" + long_datos + ">", log, Verbose);
				//escribirLog("|" + ente + "|CVC2: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				//pos+=3;
				escribirLog("|" + ente + "|CEDULA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 10)))) + ">", log, Verbose);
			}
		}
	
		
		//Mensaje 0210 Response
		else if (tipo_mensaje.equals("0210"))
		{
			int long_cuenta = 0;

			//escribirLog("|" + ente + "|LONGITUD DE LA TRAZA: <" + traza.length + ">" +  Library.byteArrayToHexString(traza), log, Verbose);
			
			//escribirLog("|" + ente + "|CONTENIDO DE LA TRAZA: <" + traza + ">", log, Verbose);
			
			//escribirLog("|" + ente + "|CONTENIDO DE LA TRAZA: <" + pos + ">", log, Verbose);
		
			codigo_proceso = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 24, 6)));
			
			codigo_proceso4 = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 16, 6)));
			//pos+=190;
			escribirLog("|" + ente + "|CODIGO PROCESO: <" + codigo_proceso + ">", log, Verbose);
						
			//esta es la trama que tre todos los MOV
			//codigo_proceso = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 194)));
			//pos-=100;
			//escribirLog("|" + ente + "|CODIGO PROCESO2 ULTIMOS MOV POS190: <" + codigo_proceso + ">", log, Verbose);
			
			//Mensaje de Consulta Ultimos Mov CTA Ahorro y CTA Corriente
			
			if (codigo_proceso.equals("311000") || codigo_proceso.equals("312000"))
			{
				//escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				//pos+=12;
				escribirLog("|" + ente + "|CODIGO PROCESO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 24, 6)))) + ">", log, Verbose);
				pos+=1;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 37, 2)))) + ">", log, Verbose);
				pos+=6;
				//escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				//pos+=4;
				escribirLog("|" + ente + "|NUMERO DE TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 30, 6)))) + ">", log, Verbose);
				//pos+=3;
				//escribirLog("|" + ente + "|REFERENCIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				//pos+=12; 
				if (campos_prendidos.indexOf("38") != -1)
				{
					escribirLog("|" + ente + "|ID RESPONSE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
					pos+=6;
				}
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, 37, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				
				escribirLog("|" + ente + "|LONGITUD DE LA TRAZA: <" + traza.length + ">" +  Library.byteArrayToHexString(traza), log, Verbose);
				
				if (codigo_respuesta.equals("00"))
				{
					int largo_data = traza.length;
					//int largo_data = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
					//pos+=3;
					escribirLog("|" + ente + "|LARGO DATA: <" + largo_data + ">", log, Verbose);
					//if (largo_data >= 200)
					//{
						//escribirLog("|" + ente + "|NUMERO CUENTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 20)))) + ">", log, Verbose);
						//pos+=20;
						//escribirLog("|" + ente + "|TIPO SALDO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 1)))) + ">", log, Verbose);
						//pos+=1;
						//escribirLog("|" + ente + "|MOVIMIENTOS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 194)))) + ">", log, Verbose);	
						//pos-=100;
					//}
				}
			}
						
			//Mensaje de Consulta Saldo
			if (codigo_proceso.equals("301000") || codigo_proceso.equals("302000"))
			{
				//escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				//pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|REFERENCIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				if (campos_prendidos.indexOf("38") != -1)
				{
					escribirLog("|" + ente + "|ID RESPONSE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
					pos+=6;
				}
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				
				if (codigo_respuesta.equals("00"))
				{
					int largo_data = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
					pos+=3;
					escribirLog("|" + ente + "|LARGO DATA: <" + largo_data + ">", log, Verbose);
					if (largo_data == 37)
					{
						escribirLog("|" + ente + "|NUMERO CUENTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 20)))) + ">", log, Verbose);
						pos+=20;
						escribirLog("|" + ente + "|TIPO SALDO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 1)))) + ">", log, Verbose);
						pos+=1;
						escribirLog("|" + ente + "|MONTO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 16)))) + ">", log, Verbose);	
						pos+=16;
					}
				}
			}
			
			//Mensaje de Consulta Saldo spara TDC despues de modicacion de campo 44 en el mensaje 0200
			/*
			if (codigo_proceso.equals("303000"))
			{
				//escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				//pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|REFERENCIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				if (campos_prendidos.indexOf("38") != -1)
				{
					escribirLog("|" + ente + "|ID RESPONSE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
					pos+=6;
				}
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				
				if (codigo_respuesta.equals("00"))
				{
					int largo_data = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
					pos+=3;
					escribirLog("|" + ente + "|LARGO DATA: <" + largo_data + ">", log, Verbose);
					if (largo_data == 37)
					{
						escribirLog("|" + ente + "|NUMERO CUENTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 20)))) + ">", log, Verbose);
						pos+=20;
						escribirLog("|" + ente + "|TIPO SALDO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 1)))) + ">", log, Verbose);
						pos+=1;
						escribirLog("|" + ente + "|MONTO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 16)))) + ">", log, Verbose);	
						pos+=16;
					}
				}
			}
			*/
			
			else if (codigo_proceso.equals("321000") || codigo_proceso.equals("322000") || codigo_proceso.equals("323000"))
			{
				//escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				//pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|REFERENCIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				if (campos_prendidos.indexOf("38") != -1)
				{
					escribirLog("|" + ente + "|ID RESPONSE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
					pos+=6;
				}
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;

				if (codigo_respuesta.equals("00"))
				{
					int largo_data = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
					pos+=3;
					escribirLog("|" + ente + "|LARGO DATA: <" + largo_data + ">", log, Verbose);
					
					int elementos = largo_data / 36;
						
					if (elementos > 0)
					{
						escribirLog("|" + ente + "|ELEMENTOS: <" + elementos + ">", log, Verbose);
						for (int i = 0; i < elementos; i++)
						{
							escribirLog("|" + ente + "|ELEMENTO NUMERO: <" + (i + 1) + ">", log, Verbose);
							escribirLog("|" + ente + "|FECHA TRAN: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 5)))) + ">", log, Verbose);
							pos+=5;
							escribirLog("|" + ente + "|SERIAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 10)))) + ">", log, Verbose);
							pos+=10;
							escribirLog("|" + ente + "|DESCRIPCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
							pos+=8;
							escribirLog("|" + ente + "|SIGNO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 1)))) + ">", log, Verbose);
							pos+=1;
							escribirLog("|" + ente + "|MONTO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
							pos+=12;
						}
					}
				}
			}
			if (codigo_proceso.equals("401020") || codigo_proceso.equals("402010"))
			{
				//escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				//pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|REFERENCIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				if (campos_prendidos.indexOf("38") != -1)
				{
					escribirLog("|" + ente + "|ID RESPONSE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
					pos+=6;
				}
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;

				if (codigo_respuesta.equals("00"))
				{
					int largo_data = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
					pos+=3;
					escribirLog("|" + ente + "|LARGO DATA: <" + largo_data + ">", log, Verbose);
					if (largo_data == 37)
					{
						escribirLog("|" + ente + "|NUMERO CUENTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 20)))) + ">", log, Verbose);
						pos+=20;
						escribirLog("|" + ente + "|TIPO SALDO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 1)))) + ">", log, Verbose);
						pos+=1;
						escribirLog("|" + ente + "|MONTO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 16)))) + ">", log, Verbose);	
						pos+=16;
					}
				}
			}
			if (codigo_proceso.equals("481010") || codigo_proceso.equals("481020") || codigo_proceso.equals("482010") || codigo_proceso.equals("482020"))
			{
				//escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				//pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|REFERENCIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
			
				if (codigo_respuesta.equals("00"))
				{
					escribirLog("|" + ente + "|LARGO DATA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
					pos+=3;
					escribirLog("|" + ente + "|NUMERO CUENTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 20)))) + ">", log, Verbose);
					pos+=20;
					escribirLog("|" + ente + "|TIPO SALDO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 1)))) + ">", log, Verbose);
					pos+=1;
					escribirLog("|" + ente + "|MONTO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 16)))) + ">", log, Verbose);
					pos+=16;
				}
			}
			if (codigo_proceso.equals("940000"))
			{
				//escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				//pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|REFERENCIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
			}
			if (codigo_proceso.equals("501000") || codigo_proceso.equals("502000"))
			{
				//escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				//pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|REFERENCIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
			}
			
			if (codigo_proceso.equals("960000"))
			{
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|REFERENCIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
			}
			
			if (codigo_proceso.equals("970000"))
			{
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				//escribirLog("|" + ente + "|POLICIA: <" + "ANTES DEL ERROR" + ">", log, Verbose);
				if (codigo_respuesta == "00")
				{
					pos+=3; //LONG CAMPO 120
					escribirLog("|" + ente + "|CEDULA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 10)))) + ">", log, Verbose);
					pos+=10;
					escribirLog("|" + ente + "|F. NAC: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
					pos+=8;
					escribirLog("|" + ente + "|TELEFONO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
					pos+=15;
				}
				
			}
		}
		//Mensaje 0100 Request
		else if (tipo_mensaje.equals("0100"))
		{
			int long_cuenta = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2))));
			escribirLog("|" + ente + "|LONG CUENTA PRIMARIA: <" + long_cuenta + ">", log, Verbose);
			pos+=2;
			escribirLog("|" + ente + "|CUENTA PRIMARIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, long_cuenta)))) + ">", log, Verbose);
			pos+=long_cuenta;
			codigo_proceso = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)));
			pos+=6;
			escribirLog("|" + ente + "|CODIGO PROCESO: <" + codigo_proceso + ">", log, Verbose);
			
			//Mensaje de Conformacion Cheques
			if (codigo_proceso.equals("032000"))
			{
				escribirLog("|" + ente + "|MONTO TRANSACCION: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|TIPO MERCANTE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|TIPO ENTRADA POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|ID RED: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|CODIGO CONDICION POS: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|ID CARD ACQ: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 15)))) + ">", log, Verbose);
				pos+=15;
				int long_datos = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3))));
				pos+=3;
				escribirLog("|" + ente + "|LONG DATOS: <" + long_datos + ">", log, Verbose);
				escribirLog("|" + ente + "|TABLE ID: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|NUM CHEQUE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
				escribirLog("|" + ente + "|NUM BANCO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 3)))) + ">", log, Verbose);
				pos+=3;
				escribirLog("|" + ente + "|NUM CUENTA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 20)))) + ">", log, Verbose);
				pos+=20;
				escribirLog("|" + ente + "|MONTO: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				escribirLog("|" + ente + "|TIPO ID: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)))) + ">", log, Verbose);
				pos+=2;
				escribirLog("|" + ente + "|NUM ID: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
			}
		}
		//Mensaje 0110 Response
		else if (tipo_mensaje.equals("0110"))
		{
			int long_cuenta = 0;
			//int long_cuenta = Integer.parseInt(new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2))));
			//escribirLog("|" + ente + "|LONG CUENTA PRIMARIA: <" + long_cuenta + ">", log, Verbose);
			//pos+=2;
			//escribirLog("|" + ente + "|CUENTA PRIMARIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, long_cuenta)))) + ">", log, Verbose);
			//pos+=long_cuenta;
			codigo_proceso = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)));
			pos+=6;
			escribirLog("|" + ente + "|CODIGO PROCESO: <" + codigo_proceso + ">", log, Verbose);
			
			//Mensaje de Conformacion Cheques
			if (codigo_proceso.equals("032000"))
			{
				escribirLog("|" + ente + "|NUMERO TRAZA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|HORA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
				pos+=6;
				escribirLog("|" + ente + "|FECHA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 4)))) + ">", log, Verbose);
				pos+=4;
				escribirLog("|" + ente + "|REFERENCIA: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 12)))) + ">", log, Verbose);
				pos+=12;
				if (campos_prendidos.indexOf("38") != -1)
				{
					escribirLog("|" + ente + "|ID RESPONSE: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 6)))) + ">", log, Verbose);
					pos+=6;
				}
				String codigo_respuesta = new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 2)));
				pos+=2;
				escribirLog("|" + ente + "|COD RESPUESTA: <" + codigo_respuesta + ">", log, Verbose);
				escribirLog("|" + ente + "|ID TERMINAL: <" + (new String(BCDConversor.BCD2char(Library.obtenerCampoArreglo(traza, pos, 8)))) + ">", log, Verbose);
				pos+=8;
			}
		}
	}
	
	public static byte[] leerCanalComunicacion(BufferedInputStream canal, String ente, PrintStream log, int Verbose, int Espera)
	{
		int disponible = 0;
		int offset = 8;
		int leido = 0;
		byte[] arrbyte_res = null;
		byte[] lectura = null;
		Merger union;
		
		try
		{
			while ((disponible = canal.available()) == 0)
			{
				//escribirLog("|" + ente + "|HAY " + disponible + " BYTES DISPONILBES PARA LEER DEL STREAM", log, Verbose);
				if (Espera != 0)
					Thread.sleep(Espera * 1000);
			}		

			escribirLog("|" + ente + "|HAY " + disponible + " BYTES DISPONILBES PARA LEER DEL STREAM", log, Verbose);

			arrbyte_res = new byte[0];
			lectura = new byte[offset];

			while(canal.read(lectura,0,offset) != -1)
			{
				union = new Merger(arrbyte_res, lectura);
				arrbyte_res = union.getArray();
				disponible = canal.available();
				
				if (disponible < offset && disponible > 0)
				{
					lectura = new byte[disponible];
					offset = disponible;
				}
				else if (disponible == 0)
					break;
			}
		}
		catch(Exception e)
		{
			escribirLog("|" + ente + "|ERROR LEYENDO DEL CANAL: " + e, log, Verbose);

		}
		
		return arrbyte_res;
	}
	
	public static String fechaActualFormato()
	{
		Calendar fActual = Calendar.getInstance();
		String fecha = "";
		
		fecha = "" + fActual.get(Calendar.YEAR);
		if ((fActual.get(Calendar.MONTH) + 1) < 10)
			fecha = fecha + "0" + (fActual.get(Calendar.MONTH) + 1);
		else
			fecha = fecha + (fActual.get(Calendar.MONTH) + 1);
		if (fActual.get(Calendar.DAY_OF_MONTH) < 10)
			fecha = fecha + "0" + fActual.get(Calendar.DAY_OF_MONTH);
		else
			fecha = fecha + fActual.get(Calendar.DAY_OF_MONTH);
		if (fActual.get(Calendar.HOUR_OF_DAY) < 10)
			fecha = fecha + "0" + fActual.get(Calendar.HOUR_OF_DAY);
		else
			fecha = fecha + fActual.get(Calendar.HOUR_OF_DAY);
		if (fActual.get(Calendar.MINUTE) < 10)
			fecha = fecha + "0" + fActual.get(Calendar.MINUTE);
		else
			fecha = fecha + fActual.get(Calendar.MINUTE);
		if (fActual.get(Calendar.SECOND) < 10)
			fecha = fecha + "0" + fActual.get(Calendar.SECOND);
		else
			fecha = fecha + fActual.get(Calendar.SECOND);
		
		return fecha;
	}
	
	public static byte[] obtenerCampoArreglo(byte[] arreglo, int inicio, int largo)
	{
		byte[] respuesta = new byte[largo];
		
		for (int i = inicio; i < (inicio + largo); i++)
		{
			respuesta[i-inicio] = arreglo[i];
		}		
		return respuesta;
	}		
	public static String camposPrendidos(byte[] bitmap)
	{
		String respuesta = "";
		int mask = 0;
		boolean primero = true;
		
		for (int i = 0; i < bitmap.length; i++)
		{
			for (int j = 7; j > -1; j--)
			{
				mask = (int) Math.pow(2,j);
				if ((BCDConversor.byte2int(bitmap[i]) & mask) == mask)
				{
					if (primero)
					{
						respuesta = respuesta + ((8 - j) + (i * 8));
						primero = !primero;
					}
					else
					{
						respuesta = respuesta + "-" + ((8 - j) + (i * 8)) ;
					}
				}
			}
		}

		return respuesta;

	}
	
	public static String camposPrendidos16(byte[] bitmap)
	{
		String respuesta = "";
		int mask = 0;
		boolean primero = true;
		
		for (int i = 0; i < bitmap.length; i++)
		{
			for (int j = 15; j > -1; j--)
			{
				mask = (int) Math.pow(2,j);
				if ((BCDConversor.byte2int(bitmap[i]) & mask) == mask)
				{
					if (primero)
					{
						respuesta = respuesta + ((8 - j) + (i * 8));
						primero = !primero;
					}
					else
					{
						respuesta = respuesta + "-" + ((8 - j) + (i * 8)) ;
					}
				}
			}
		}

		return respuesta;

	}
	
	public static String CompletoCerosIzquierda(String cadena, int largo_necesario)
	{
		String respuesta = cadena;
		
		for (int i = cadena.length(); i < largo_necesario; i++)
		{
			respuesta = "0" + respuesta;
		}
		
		return respuesta;
	}
	
	public static String CompletoEspaciosDerecha(String cadena, int largo_necesario)
	{
		String respuesta = cadena;
		
		for (int i = cadena.length(); i < largo_necesario; i++)
		{
			respuesta = respuesta + " ";
		}
		
		return respuesta;
	}

	public static void escribirLog(String texto, PrintStream log, int Tipo)
	{
		if (Tipo == 1)
			System.out.println(fechaActualFormato() + texto);
		else
			log.println(fechaActualFormato() + texto);
	}
	
	public static String descripcionError(String codigo_error)
	{
		String descripcion_error = "";
		//Codigo de error agregar nuevos
		if (codigo_error.equals("04"))
			descripcion_error = "CAPTURE TARJETA";
		else if (codigo_error.equals("05"))
			descripcion_error = "CEDULA NO COINCIDE";
		else if (codigo_error.equals("12"))
			descripcion_error = "TRANSACCION INVALIDA";
		else if (codigo_error.equals("13"))
			descripcion_error = "MONTO INVALIDO";
		else if (codigo_error.equals("14"))
			descripcion_error = "TARJETA NO EXISTE";
		else if (codigo_error.equals("19"))
			descripcion_error = "INTENTE DE NUEVO LA TRANSACCION";
		else if (codigo_error.equals("25"))
			descripcion_error = "NO UBICA REGISTRO ORIGINAL";
		else if (codigo_error.equals("30"))
			descripcion_error = "ERROR EN FORMATO";
		else if (codigo_error.equals("31"))
			descripcion_error = "BANCO NO SOPORTADO";
		else if (codigo_error.equals("41"))
			descripcion_error = "TARJETA PERDIDA";
		else if (codigo_error.equals("43"))
			descripcion_error = "TARJETA ROBADA - RETENER";
		else if (codigo_error.equals("50"))
			descripcion_error = "CLIENTE NO EXISTE";
		else if (codigo_error.equals("51"))
			descripcion_error = "NEGADA - FONDO INSUFICIENTE";
		else if (codigo_error.equals("52"))
			descripcion_error = "ERROR EN CREACION";
		else if (codigo_error.equals("53"))
			descripcion_error = "CLIENTE YA EXISTE";
		else if (codigo_error.equals("54"))
			descripcion_error = "TARJETA VENCIDA";
		else if (codigo_error.equals("55"))
			descripcion_error = "PIN ERRADO";
		else if (codigo_error.equals("56"))
			descripcion_error = "CLAVE YA UTILIZADA";
		else if (codigo_error.equals("57"))
			descripcion_error = "TRANSACCION NO PERMITIDA";
		else if (codigo_error.equals("58"))
			descripcion_error = "PIN EXPIRO POR MAX NRO DIAS (>180)";
		else if (codigo_error.equals("59"))
			descripcion_error = "NO SE PUDO ACTUALIZAR CLAVE";
		else if (codigo_error.equals("60"))
			descripcion_error = "CLAVE NO ACTIVA PARA BLOQUEO";
		else if (codigo_error.equals("61"))
			descripcion_error = "EXCEDE EL LIMITE DE RETIRO";
		else if (codigo_error.equals("62"))
			descripcion_error = "TARJETA RESTRINGIDA";
		else if (codigo_error.equals("63"))
			descripcion_error = "CLAVE ESTA INACTIVA";
		else if (codigo_error.equals("64"))
			descripcion_error = "CLAVE ESTA BLOQUEADA";
		else if (codigo_error.equals("66"))
			descripcion_error = "CLAVE ESTA RESETEADA";
		else if (codigo_error.equals("67"))
			descripcion_error = "CLAVE ESTA SUSPENDIDA";
		else if (codigo_error.equals("68"))
			descripcion_error = "ESTATUS INVALIDO";
		else if (codigo_error.equals("69"))
			descripcion_error = "CON CONDICION CAMBIAR PIN";
		else if (codigo_error.equals("70"))
			descripcion_error = "ERROR DESCONOCIDO";
		else if (codigo_error.equals("75"))
			descripcion_error = "EXCEDE INTENTOS PIN";
		else if (codigo_error.equals("76"))
			descripcion_error = "CODIGO DE PRODUCTO INVALIDO";
		else if (codigo_error.equals("78"))
			descripcion_error = "CUENTA ESPECIFICADA INVALIDA";
		else if (codigo_error.equals("77"))
			descripcion_error = "ERROR EN RECONCILIACION";
		else if (codigo_error.equals("80"))
			descripcion_error = "NUMERO DE BATCH NO EXISTE";
		else if (codigo_error.equals("89"))
			descripcion_error = "NUMERO DE TERMINAL INVALIDO";
		else if (codigo_error.equals("91"))
			descripcion_error = "EMISOR NO ESTA OPERATIVO";
		else if (codigo_error.equals("94"))
			descripcion_error = "TRANSMISION DUPLICADA";
		else if (codigo_error.equals("95"))
			descripcion_error = "ERROR EN RECONCILIACION - BATCH UPLOAD COMIENZA";
		else if (codigo_error.equals("96"))
			descripcion_error = "ERROR DEL SISTEMA";
		else if (codigo_error.equals("I01"))
			descripcion_error = "CAMPO LONGITUD ERRONEA (ISOSERVER)";
		else if (codigo_error.equals("I02"))
			descripcion_error = "LONGITUD PIN INVALIDA (ISOSERVER)";
		else if (codigo_error.equals("I03"))
			descripcion_error = "MAL FORMATO PETICION (ISOSERVER)";
		else if (codigo_error.equals("I04"))
			descripcion_error = "SE ESPERABA CAMPO NUMERICO (ISOSERVER)";
		else if (codigo_error.equals("I05"))
			descripcion_error = "CAMPO EN MAL FORMATO (ISOSERVER)";
		else if (codigo_error.equals("I06"))
			descripcion_error = "CODIGO DE PROCESO INVALIDO (ISOSERVER)";
		else if (codigo_error.equals("I07"))
			descripcion_error = "LONGITUD TARJETA INVALIDA (ISOSERVER)";
		else if (codigo_error.equals("IMR"))
			descripcion_error = "MALA RESPUESTA DEL SWITCH (ISOSERVER)";
		else
			descripcion_error = "ERROR DESCONOCIDO";
		
		return descripcion_error;
	}

	static String mensajeServicio(String Servicio)
	{
		String msgServicio = "";
		String TipoServicio = "";
		String DescServicio = "";

		if (Servicio.equals("0201"))
		{
			TipoServicio = "0201";
			DescServicio = "VISA                          ";
			msgServicio = CompletoCerosIzquierda(Long.toString(TipoServicio.length() + DescServicio.length()),3) + TipoServicio + DescServicio;
		}
		if (Servicio.equals("0202"))
		{
			TipoServicio = "0202";
			DescServicio = "MASTER CARD                   ";
			msgServicio = CompletoCerosIzquierda(Long.toString(TipoServicio.length() + DescServicio.length()),3) + TipoServicio + DescServicio;
		}

		return msgServicio;
	}

	static String mensajeAutorizacionCheque(String NumeroCheque, String NumeroCuenta, String Monto, String TipoID, String ID)
	{
		String msgAutorizacionCheque = "";
		String msgNumeroCheque = "";
		String msgNumeroCuenta = "";
		String msgMonto = "";
		String msgID = "";
		
		msgNumeroCheque = CompletoCerosIzquierda(NumeroCheque,8);
		msgNumeroCuenta = CompletoCerosIzquierda(NumeroCuenta,20);
		msgMonto = CompletoCerosIzquierda(Monto,12);
		msgID = CompletoEspaciosDerecha(ID,12);

		msgAutorizacionCheque = CompletoCerosIzquierda(Long.toString(59),3) + "65" + msgNumeroCheque + "168" + msgNumeroCuenta + msgMonto + TipoID + msgID;

		return msgAutorizacionCheque;	
	}
}