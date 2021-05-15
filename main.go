package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"
	//"github.com/go-ldap/ldap/v3"
)

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	//Token	string	`json:"token"`
}

type infoReq struct {
	Token string `json:"token"`
}

type Data struct {
	Token string `json:"token"`
}
type loginResp struct {
	Code	int	`json:"code"`
	Status	string	`json:"status"`
	Msg   string `json:"msg"`
	Data	`json:"data"`
	IP    string `json:"ip"`
}

type InfoData struct {
	Avatar	string `json:"avatar"`
	Introduction	string 	`json:"introduction"`
	Name	string	`json:"name"`
	Roles	[]string	`json:"roles"`
}
type infoResp struct {
	Code	int 	`json:"code"`
	InfoData	`json:"data"`
}
type registerReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Tel		string	`json:"tel""`
	SMSCode	string	`json:"sms_code"`
	EncryptedSMSCode	string `json:"encrypted_sms_code"`
}

type registerResp struct {
	Msg   string `json:"msg"`
	Token string `json:"token"`
	IP    string `json:"ip"`
}

type sendShortMessageCodeReq struct {
	PhoneNumber string `json:"phone_number"`
}

type sendShortMessageCodeResp struct {
	EncryptedSMSCode	string `json:"encrypted_sms_code"`
}

type registerClass struct {
	registerReq
	path string
}

type loginClass struct {
	loginReq
	Token string
	path  string
}

func newRegisterObj(params *registerReq) *registerClass {
	return &registerClass{
		registerReq: *params,
		path:        "password.csv",
	}
}

func newLoginObj(ctx *gin.Context, params *loginReq) *loginClass {
	return &loginClass{
		loginReq: *params,
		Token:    ctx.GetHeader("token"),
		path:     "password.csv",
	}
}

func Encode(encodeString string) (string, error) {
	ttl := "10000"
	day, err := strconv.Atoi(ttl)
	if err != nil {
		return "", err
	}
	time.Now().Add(time.Duration(day*24) * time.Hour)
	expDate, err := time.Parse("2006-01-02 15:04:05", time.Now().AddDate(0, 1, 0).Format("2006-01-02")+" 05:00:00")
	if err != nil {
		return "", err
	}
	exp := expDate.Unix()
	BaseUrl := "www.chenguo.com"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": BaseUrl,
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"exp": exp,
		"sub": encodeString,
	})

	// Sign and get the complete encoded token as a string using the secret
	key := "chenguo_key"
	tokenString, err := token.SignedString([]byte(key))

	return tokenString, err
}

func Decode(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err := fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			fmt.Println("Decode", tokenString, err)
			return nil, err
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		key := "chenguo_key"
		return []byte(key), nil
	})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return cast.ToString(claims["sub"]), nil
	}
	return "", nil
}

// 校验用户名是否存在
func (obj *registerClass) usernameExist(ctx *gin.Context) (ok bool, err error) {
	file, err := os.Open(obj.path)
	defer file.Close()
	csvReader := csv.NewReader(file)
	rows, err := csvReader.ReadAll()
	if err != nil {
		fmt.Printf("ReadAll err=[%+v]\n", err)
		return
	}
	for _, row := range rows {
		if obj.Username == row[0] {
			return true, nil
		}
	}
	return false, nil
}

// 存储用户名和密码
func (obj *registerClass) saveInfo(ctx *gin.Context) error {
	file, err := os.OpenFile(obj.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()
	if err != nil {
		fmt.Printf("open file err=[%+v]\n", err)
		return err
	}
	csvWriter := csv.NewWriter(file)
	csvWriter.Write([]string{obj.Username, obj.Password})
	csvWriter.Flush()
	fmt.Println("存储完毕")
	return nil
}

// 初始化存储文件
func (obj *registerClass) initStorage(ctx *gin.Context) error {
	file, err := os.OpenFile(obj.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()
	return err
}

// 用户名和密码文本检查
func (obj *registerClass) textCheck(ctx *gin.Context) (msg string, err error) {
	for _, v := range obj.Username {
		if ',' == v {
			return "用户名中不能有逗号", nil
		}
	}
	for _, v := range obj.Password {
		if ',' == v {
			return "密码中不能有逗号", nil
		}
	}
	return
}

// 初始化存储文件
func (obj *loginClass) initStorage(ctx *gin.Context) error {
	file, err := os.OpenFile(obj.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()
	return err
}

func (obj *loginClass) loginWithToken(ctx *gin.Context) (resp loginResp, err error) {
	usernameByDecode, err := Decode(obj.Token)
	if err != nil {
		fmt.Printf("Decode err=[%+v]\n", err)
		resp.Msg = "Token错误"
		return
	}
	resp.Code = 20000
	resp.Status = "success"
	resp.Msg = fmt.Sprintf("%+v 登录成功", usernameByDecode)
	resp.Token = obj.Token
	return
}
func (obj *loginClass) loginWithPassword(ctx *gin.Context) (resp loginResp, err error) {
	file, err := os.Open(obj.path)
	defer file.Close()
	csvReader := csv.NewReader(file)
	rows, err := csvReader.ReadAll()
	if err != nil {
		fmt.Printf("ReadAll err=[%+v]\n", err)
		return
	}
	for _, row := range rows {
		if obj.Username == row[0] {
			if obj.Password == row[1] {
				resp.Data.Token, err = Encode(obj.Username)
				if err != nil {
					fmt.Printf("Encode err=[%+v]\n", err)
					return
				}
				resp.Code = 20000
				resp.Data.Token = "editor-token"
				resp.Status = "success"
				resp.Msg = "登录成功"
			} else {
				resp.Msg = "密码错误"
			}
			break
		}
	}
	return
}
func sendShortMessageCodeService(ctx *gin.Context, params *sendShortMessageCodeReq) (resp sendShortMessageCodeResp, err error) {
	// todo 设置随机种子
	SMSCode := rand.Intn(1000000)
	str := "nothing"
	// todo 暂时不用发送短信
	//str, err := component.SendSms(params.PhoneNumber, SMSCode, 5)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("!!!!!!!!!!!!!!!!!")
	fmt.Println(str)
	fmt.Printf("为 %v 生成的验证码为 %v\n", params.PhoneNumber, SMSCode)
	// todo 只传验证码的话还是有可能被伪造身份，可以多传一个手机号
	tmp := md5.Sum([]byte(cast.ToString(SMSCode) + "chenguo_md5_key"))
	resp.EncryptedSMSCode = base64.StdEncoding.EncodeToString(tmp[:])
	//resp.EncryptedSMSCode = cast.ToString(SMSCode)
	fmt.Printf("%v\n", resp)
	fmt.Println("!!!!!!!!!!!!!!!!!")
	return
}
func loginService(ctx *gin.Context, params *loginReq) (resp loginResp, err error) {
	resp.IP = ctx.ClientIP()
	obj := newLoginObj(ctx, params)
	err = obj.initStorage(ctx)
	if err != nil {
		fmt.Printf("initStorage err=[%+v]\n", err)
		return
	}

	if "" != obj.Token {
		resp, err = obj.loginWithToken(ctx)
		if err != nil {
			return
		}
	} else {
		resp, err = obj.loginWithPassword(ctx)
		if err != nil {
			return
		}
	}
	return
}

func infoService(ctx *gin.Context, params *infoReq) (resp infoResp, err error) {
	fmt.Println("!!!!!!!!!!!!!!")
	fmt.Printf("%+v\n", ctx)
	fmt.Printf("%+v\n", params)
	fmt.Println(ctx.GetHeader("X-Token"))
	fmt.Println("!!!!!!!!!!!!!!")
	resp.Code = 20000
	resp.Avatar = "https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif"
	resp.Introduction = "I am an editor"
	resp.Name = "Normal Editor"
	resp.Roles = []string{"editor"}
	return
	//obj := newLoginObj(ctx, params)
	//err = obj.initStorage(ctx)
	//if err != nil {
	//	fmt.Printf("initStorage err=[%+v]\n", err)
	//	return
	//}
	//
	//if "" != obj.Token {
	//	resp, err = obj.loginWithToken(ctx)
	//	if err != nil {
	//		return
	//	}
	//} else {
	//	resp, err = obj.loginWithPassword(ctx)
	//	if err != nil {
	//		return
	//	}
	//}
	//return
}

func registerService(ctx *gin.Context, params *registerReq) (resp registerResp, err error) {
	resp.IP = ctx.ClientIP()
	tmp := md5.Sum([]byte(params.SMSCode + "chenguo_md5_key"))
	if base64.StdEncoding.EncodeToString(tmp[:]) != params.EncryptedSMSCode {
		resp.Msg = "验证码错误"
		return
	}
	obj := newRegisterObj(params)

	err = obj.initStorage(ctx)
	if err != nil {
		fmt.Printf("initStorage err=[%+v]\n", err)
	}

	isExist, err := obj.usernameExist(ctx)
	if err != nil {
		fmt.Printf("usernameExist err=[%+v]\n", err)
		return
	}
	if isExist {
		resp.Msg = "用户名已存在"
		return
	}

	msg, err := obj.textCheck(ctx)
	if "" != msg {
		resp.Msg = msg
		return
	}

	err = obj.saveInfo(ctx)
	if err != nil {
		fmt.Printf("saveInfo err=[%+v]\n", err)
		return
	}
	resp.Msg = "注册成功"
	resp.Token, err = Encode(obj.Username)
	if err != nil {
		fmt.Printf("Encode err=[%+v]\n", err)
		return
	}
	return
}

func registerController(ctx *gin.Context) {
	// 参数绑定
	params := registerReq{}
	err := ctx.ShouldBind(&params)
	if err != nil {
		fmt.Printf("bind err=[%+v]\n", err)
		return
	}
	fmt.Printf("%+v", params)

	// service
	resp, err := registerService(ctx, &params)
	if err != nil {
		fmt.Printf("registerService err=[%+v]\n", err)
		return
	}
	ctx.JSON(200, resp)
}


func loginController(ctx *gin.Context) {
	// 参数绑定
	params := loginReq{}
	err := ctx.ShouldBind(&params)
	if err != nil {
		fmt.Printf("bind err=[%+v]\n", err)
		return
	}
	fmt.Printf("%+v", params)

	// service
	resp, err := loginService(ctx, &params)
	if err != nil {
		fmt.Printf("loginService err=[%+v]\n", err)
	}
	ctx.JSON(200, resp)
}

func infoController(ctx *gin.Context) {
	// 参数绑定
	params := infoReq{}
	err := ctx.ShouldBind(&params)
	if err != nil {
		fmt.Printf("bind err=[%+v]\n", err)
		return
	}
	fmt.Printf("%+v", params)

	// service
	resp, err := infoService(ctx, &params)
	if err != nil {
		fmt.Printf("loginService err=[%+v]\n", err)
	}
	ctx.JSON(200, resp)
}
func sendShortMessageCodeController(ctx *gin.Context) {
	// 参数绑定
	params := sendShortMessageCodeReq{}
	err := ctx.ShouldBind(&params)
	if err != nil {
		fmt.Printf("bind err=[%+v]\n", err)
		return
	}
	fmt.Printf("%+v", params)

	// service
	resp, err := sendShortMessageCodeService(ctx, &params)
	if err != nil {
		fmt.Printf("loginService err=[%+v]\n", err)
	}
	fmt.Println("...............")
	fmt.Println(resp)
	fmt.Println("...............")
	ctx.JSON(200, resp)
}

func main() {
	router := gin.Default()
	//router.Use(cors.Default())

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:9527"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "X-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		//AllowOriginFunc: func(origin string) bool {
		//	return origin == "https://github.com"
		//},
		MaxAge: 12 * time.Hour,
	}))
	router.GET("/baidu", func(context *gin.Context) {
		context.Redirect(http.StatusMovedPermanently, "http://baidu.com/")
	})
	router.POST("/getdata", func(context *gin.Context) {
		context.JSON(200, struct {
			Message string `json:"message"`
		}{
			"Hello, ",
		})
	})
	router.LoadHTMLFiles("html/index.html")
	router.GET("/html", func(context *gin.Context) {
		context.HTML(200, "index.html", "cg")
	})
	router.GET("/info", infoController)
	router.POST("/register", registerController)
	router.POST("/login", loginController)
	router.POST("/sendSMSCode", sendShortMessageCodeController)
	router.Run(":2312")
}
