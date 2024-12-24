package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	crypto_rand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/avast/retry-go"
	"github.com/gin-gonic/gin"
	"github.com/google/go-github/v62/github"
	"github.com/robfig/cron/v3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/nacl/box"
	"gopkg.in/yaml.v3"
	template2 "html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"time"
)

var cfg Cfg
var tmpPath = os.TempDir()
var cronManager = cron.New(cron.WithSeconds())

const readmeTemplate = `# {{.Title}}

**上一次更新：{{.LastUpdate}}**

## 应用列表

| {{range .Table.Headers}}{{.}} | {{end}}
| {{range .Table.Headers}}---| {{end}}
{{range .Table.Rows}}| {{range .}}{{.}} | {{end}}
{{end}}
`
const clearHistoryWorkflowYml = `
name: Clear Git History
on:
  schedule:
    - cron: '10 22 * * *'
  workflow_dispatch:
jobs:
  clear-history:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
          fetch-depth: 0  # Fetch all history for all branches and tags
          token: ${{ secrets.PAT_TOKEN }}
      - name: Get default branch
        id: default_branch
        run: echo "::set-output name=branch::$(echo ${GITHUB_REF#refs/heads/})"
      - name: Remove git history
        env:
          DEFAULT_BRANCH: ${{ steps.default_branch.outputs.branch }}
        run: |
          git config --local user.email "github-actions[bot]@users.noreply.github.com"
          git config --local user.name "github-actions[bot]"
          git checkout --orphan tmp
          git add -A				# Add all files and commit them
          git commit -m "Reset all files"
          git branch -D $DEFAULT_BRANCH		# Deletes the default branch
          git branch -m $DEFAULT_BRANCH		# Rename the current branch to defaul
      - name: Push changes
        uses: ad-m/github-push-action@master
        with:
          force: true
          branch: ${{ github.ref }}
          github_token: ${{ secrets.PAT_TOKEN }}
`

func main() {
	initConfig()
	if cfg.BakRepo != "" && cfg.BakRepoOwner != "" && cfg.BakGithubToken != "" {
		LogEnv()
		if cfg.StartWithRestore == "1" {
			if cfg.BakDelayRestore != "" {
				//启动时延时还原数据
				delay, _ := strconv.Atoi(cfg.BakDelayRestore)
				time.Sleep(time.Duration(delay) * time.Minute)
			}
			//Restore()
		}
		//定时备份
		//CronTask()
		if cfg.RunMode == "2" {
			if cfg.BakLog == "1" {
				gin.SetMode(gin.DebugMode)
			} else {
				gin.SetMode(gin.ReleaseMode)
			}
			r := gin.Default()
			r.StaticFile("/logo.svg", "./static/logo.svg")
			t, _ := template2.New("custom").Delims("<<", ">>").ParseGlob("templates/*")
			r.SetHTMLTemplate(t)
			authorized := r.Group("/", gin.BasicAuth(gin.Accounts{
				"admin": cfg.WebPwd,
			}))
			authorized.GET("/", func(c *gin.Context) {
				c.HTML(http.StatusOK, "index.html", gin.H{
					"title": "backup2gh",
				})
				//test
				/*data, err := os.ReadFile("D:\\backup2gh\\templates\\index.html")
				if err != nil {
					fmt.Println(err)
					return
				}
				c.Data(http.StatusOK, "text/html; charset=utf-8", data)*/
			})
			authorized.GET("/config", func(c *gin.Context) {
				c.JSON(http.StatusOK, cfg)
			})
			authorized.GET("/backups", func(c *gin.Context) {
				c.JSON(http.StatusOK, getBackUps())
			})
			authorized.GET("/backup/run", func(c *gin.Context) {
				go Backup()
				c.JSON(http.StatusOK, gin.H{})
			})
			authorized.POST("/config", func(c *gin.Context) {
				_ = c.BindJSON(&cfg)
				c.JSON(http.StatusOK, gin.H{})
				LogEnv()
			})
			authorized.POST("/backup/delete", func(c *gin.Context) {
				content := github.RepositoryContent{}
				_ = c.BindJSON(&content)
				err := deleteBackup(content)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{})
				} else {
					c.JSON(http.StatusOK, gin.H{})
				}
			})
			authorized.POST("/backup/restore", func(c *gin.Context) {
				content := github.RepositoryContent{}
				_ = c.BindJSON(&content)
				RestoreFromContent(&content)
				c.JSON(http.StatusOK, gin.H{})
			})
			authorized.GET("/config/export", func(c *gin.Context) {
				exportType := c.Query("type")
				name := "config.yaml"
				if exportType == "1" {
					name = "env.txt"
				}
				c.Header("Content-Disposition", "attachment; filename="+url.QueryEscape(name))
				c.Header("Content-Transfer-Encoding", "binary")
				c.Data(http.StatusOK, "application/octet-stream", getConfigData(exportType))
			})
			_ = r.Run(fmt.Sprintf(":%s", cfg.WebPort))
		} else {
			defer cronManager.Stop()
			select {}
		}
	} else {
		debugLog("No Valid Config found!")
	}
}

func getConfigData(exportType string) []byte {
	if exportType == "1" {
		v := reflect.ValueOf(cfg)
		t := v.Type()
		var envText string
		for i := 0; i < v.NumField(); i++ {
			key := t.Field(i).Tag.Get("yaml")
			value := fmt.Sprintf("%v", v.Field(i).Interface())
			key = strings.ToUpper(key)
			envText += fmt.Sprintf("%s=%s\n", key, value)
		}
		return []byte(envText)
	} else {
		data, err := yaml.Marshal(&cfg)
		if err != nil {
			debugLog("Error marshalling YAML:", err)
			return nil
		}
		return data
	}
}

func deleteBackup(dc github.RepositoryContent) error {
	ctx := context.Background()
	client, err := getClient()
	commitMessage := "Delete file by api."
	if err != nil {
		log.Printf("Delete backup err: %v", err)
		return err
	}
	_, _, err = client.Repositories.DeleteFile(ctx, cfg.BakRepoOwner, cfg.BakRepo, *dc.Path, &github.RepositoryContentFileOptions{
		Message: &commitMessage,
		SHA:     dc.SHA,
		Branch:  &cfg.BakBranch,
	})
	return err
}
func getClient() (*github.Client, error) {
	proxyURL, err := url.Parse(cfg.BakProxy)
	if err != nil {
		log.Printf("Failed to parse proxy URL: %v", err)
		return nil, err
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	// 创建带有代理的 HTTP 客户端
	httpClient := &http.Client{
		Transport: transport,
	}
	if cfg.BakProxy == "" {
		httpClient = nil
	}
	client := github.NewClient(httpClient).WithAuthToken(cfg.BakGithubToken)
	return client, nil
}

func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			viper.BindEnv("AppName", "BAK_APP_NAME")
			viper.BindEnv("BakCron", "BAK_CRON")
			viper.BindEnv("BakBranch", "BAK_BRANCH")
			viper.BindEnv("BakDataDir", "BAK_DATA_DIR")
			viper.BindEnv("BakGithubToken", "BAK_GITHUB_TOKEN")
			viper.BindEnv("BakProxy", "BAK_PROXY")
			viper.BindEnv("BakLog", "BAK_LOG")
			viper.BindEnv("BakMaxCount", "BAK_MAX_COUNT")
			viper.BindEnv("BakRepo", "BAK_REPO")
			viper.BindEnv("BakRepoOwner", "BAK_REPO_OWNER")
			viper.BindEnv("BakDelayRestore", "BAK_DELAY_RESTORE")
			viper.BindEnv("RunMode", "RUN_MODE")
			viper.BindEnv("WebPort", "WEB_PORT")
			viper.BindEnv("WebPwd", "WEB_PWD")
			viper.BindEnv("StartWithRestore", "START_WITH_RESTORE")
		}
	} else {
		viper.ReadInConfig()
		debugLog("读取到config.yaml文件")
	}
	viper.SetDefault("BakDelayRestore", "0")
	viper.SetDefault("StartWithRestore", "1")
	viper.SetDefault("BakLog", "0")
	viper.SetDefault("BakMaxCount", "5")
	viper.SetDefault("BakBranch", "main")
	viper.SetDefault("BakCron", "0 0 0/1 * * ?")
	viper.SetDefault("RunMode", "1")
	viper.SetDefault("RunPort", "8088")
	_ = viper.Unmarshal(&cfg)
}

type Cfg struct {
	AppName          string `yaml:"bak_app_name" json:"bak_app_name" mapstructure:"bak_app_name"`
	BakCron          string `yaml:"bak_cron" json:"bak_cron" mapstructure:"bak_cron"`
	BakBranch        string `yaml:"bak_branch" json:"bak_branch" mapstructure:"bak_branch"`
	BakDataDir       string `yaml:"bak_data_dir" json:"bak_data_dir" mapstructure:"bak_data_dir"`
	BakGithubToken   string `yaml:"bak_github_token" json:"bak_github_token" mapstructure:"bak_github_token"`
	BakLog           string `yaml:"bak_log" json:"bak_log" mapstructure:"bak_log"`
	BakMaxCount      string `yaml:"bak_max_count" json:"bak_max_count" mapstructure:"bak_max_count"`
	BakProxy         string `yaml:"bak_proxy" json:"bak_proxy" mapstructure:"bak_proxy"`
	BakRepo          string `yaml:"bak_repo" json:"bak_repo" mapstructure:"bak_repo"`
	BakRepoOwner     string `yaml:"bak_repo_owner" json:"bak_repo_owner" mapstructure:"bak_repo_owner"`
	BakDelayRestore  string `yaml:"bak_delay_restore" json:"bak_delay_restore" mapstructure:"bak_delay_restore"`
	RunMode          string `yaml:"run_mode" json:"run_mode" mapstructure:"run_mode"`
	WebPort          string `yaml:"web_port" json:"web_port" mapstructure:"web_port"`
	WebPwd           string `yaml:"web_pwd" json:"web_pwd" mapstructure:"web_pwd"`
	StartWithRestore string `yaml:"start_with_restore" json:"start_with_restore" mapstructure:"start_with_restore"`
}

func LogEnv() {
	debugLog("BAK_APP_NAME：%s", cfg.AppName)
	debugLog("BAK_REPO_OWNER：%s", cfg.BakRepoOwner)
	debugLog("BAK_REPO：%s", cfg.BakRepo)
	debugLog("BAK_GITHUB_TOKEN：%s", "***********")
	debugLog("BAK_DATA_DIR：%s", cfg.BakDataDir)
	debugLog("BAK_PROXY：%s", cfg.BakProxy)
	debugLog("BAK_CRON：%s", cfg.BakCron)
	debugLog("BAK_MAX_COUNT：%s", cfg.BakMaxCount)
	debugLog("BAK_LOG：%s", cfg.BakLog)
	debugLog("BAK_BRANCH：%s", cfg.BakBranch)
	debugLog("BAK_DELAY_RESTORE：%s", cfg.BakDelayRestore)
	debugLog("TMP_PATH：%s", tmpPath)
	debugLog("RUN_MODE：%s", cfg.RunMode)
	debugLog("RUN_PORT：%s", cfg.WebPort)
	debugLog("WEB_PWD：%s", "****")
}
func CronTask() {
	cronManager.AddFunc(cfg.BakCron, func() {
		retry.Do(
			func() error {
				return Backup()
			},
			retry.Delay(3*time.Second),
			retry.Attempts(3),
			retry.DelayType(retry.FixedDelay),
		)
	})
	cronManager.Start()
}
func Restore() {
	ctx := context.Background()
	client, _ := getClient()
	_, dirContents, _, _ := client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, cfg.AppName, nil)
	if len(dirContents) > 0 {
		//取最后一个文件
		content := dirContents[len(dirContents)-1]
		RestoreFromContent(content)
	}
}

func RestoreFromContent(content *github.RepositoryContent) {
	debugLog("Get Last Backup File: %s， Size: %d，Url: %s", content.GetPath(), content.GetSize(), content.GetDownloadURL())
	url := content.GetDownloadURL()
	//下载、解压文件
	zipFilePath := filepath.Join(tmpPath, *content.Name)
	DownloadFile(url, zipFilePath)
	debugLog("DownloadFile: %s", zipFilePath)
	Unzip(zipFilePath, cfg.BakDataDir)
	os.Remove(zipFilePath)
	debugLog("Unzip && Remove: %s", zipFilePath)
}

func debugLog(str string, v ...any) {
	if cfg.BakLog == "1" {
		if v != nil {
			log.Printf(str, v...)
		} else {
			log.Println(str)
		}
	}
}
func getBackUps() []*github.RepositoryContent {
	ctx := context.Background()
	client, _ := getClient()
	_, dirContents, _, _ := client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, cfg.AppName, &github.RepositoryContentGetOptions{Ref: cfg.BakBranch})
	return dirContents
}

func Backup() error {
	ctx := context.Background()
	chineseTimeStr(time.Now(), "200601021504")
	fileName := chineseTimeStr(time.Now(), "200601021504") + ".zip"
	zipFilePath := filepath.Join(tmpPath, fileName)
	debugLog("Start Zip File: %s", zipFilePath)
	Zip(cfg.BakDataDir, zipFilePath)
	commitMessage := "Add File"
	fileContent, _ := os.ReadFile(zipFilePath)
	client, err := getClient()
	if err != nil {
		return err
	}
	_, resp, _ := client.Repositories.Get(ctx, cfg.BakRepoOwner, cfg.BakRepo)
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		if _, _, err = client.Repositories.Create(ctx, "", &github.Repository{
			Name:          github.String(cfg.BakRepo),
			Private:       github.Bool(true),
			DefaultBranch: github.String(cfg.BakBranch),
		}); err != nil {
			log.Printf("failed to create repo: %s", err)
		}
		debugLog("Create Repo: %s", cfg.BakRepo)
	}
	err = AddOrUpdateFile(client, ctx, cfg.BakBranch, cfg.AppName+"/"+fileName, fileContent)
	if err != nil {
		return err
	}
	err = os.Remove(zipFilePath)
	//查询仓库中备份文件数量
	count, err := strconv.Atoi(cfg.BakMaxCount)
	if err != nil {
		count = 5
	}
	_, dirContents, _, _ := client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, cfg.AppName, &github.RepositoryContentGetOptions{Ref: cfg.BakBranch})
	commitMessage = "clean file"
	if len(dirContents) > count {
		for i, dc := range dirContents {
			if i+1 <= len(dirContents)-count {
				client.Repositories.DeleteFile(ctx, cfg.BakRepoOwner, cfg.BakRepo, *dc.Path, &github.RepositoryContentFileOptions{
					Message: &commitMessage,
					SHA:     dc.SHA,
					Branch:  &cfg.BakBranch,
				})
			}

		}

	}
	_, dirContents, _, _ = client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, "", &github.RepositoryContentGetOptions{Ref: cfg.BakBranch})
	rows := [][]string{}
	isFirstInit := true
	if len(dirContents) > 0 {
		i := 0
		for _, dc := range dirContents {
			if dc.GetName() == ".github" {
				isFirstInit = false
			}
			if dc.GetType() == "dir" && dc.GetName() != ".github" {
				commits, _, _ := client.Repositories.ListCommits(ctx, cfg.BakRepoOwner, cfg.BakRepo, &github.CommitsListOptions{
					Path: dc.GetPath(),
					ListOptions: github.ListOptions{
						PerPage: 1,
					},
				})
				commitDate := commits[0].GetCommit().GetAuthor().GetDate()
				_, dcs, _, _ := client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, dc.GetPath(), &github.RepositoryContentGetOptions{Ref: cfg.BakBranch})
				row := []string{}
				i++
				row = append(row,
					fmt.Sprintf("%d", i),
					dc.GetName(),
					chineseTimeStr(commitDate.Time, "2006-01-02 15:04:05"),
					fmt.Sprintf("[%s](%s)", dcs[len(dcs)-1].GetName(), dcs[len(dcs)-1].GetDownloadURL()))
				rows = append(rows, row)
			}
		}
	}
	_, dirContents, _, _ = client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, "", &github.RepositoryContentGetOptions{Ref: cfg.BakBranch})
	if len(rows) > 0 {
		readmeContent := ReadmeData{
			Title:      cfg.BakRepo,
			LastUpdate: chineseTimeStr(time.Now(), "2006-01-02 15:04:05"),
			Table: TableData{
				Headers: []string{"序号", "应用名称", "更新时间", "最近一次备份"},
				Rows:    rows,
			},
		}
		tmpl, _ := template.New("readme").Parse(readmeTemplate)
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, readmeContent)
		if err != nil {
			panic(err)
		}
		readmeStr := buf.String()
		debugLog(readmeStr)
		_ = AddOrUpdateFile(client, ctx, cfg.BakBranch, "README.md", []byte(readmeStr))
	}
	if isFirstInit {
		_ = AddOrUpdateFile(client, ctx, cfg.BakBranch, ".github/workflows/clear-history.yml", []byte(clearHistoryWorkflowYml))
		input := &github.DefaultWorkflowPermissionRepository{
			DefaultWorkflowPermissions: github.String("write"),
		}
		_, _, _ = client.Repositories.EditDefaultWorkflowPermissions(ctx, cfg.BakRepoOwner, cfg.BakRepo, *input)
		_ = addRepoSecret(ctx, client, cfg.BakRepoOwner, cfg.BakRepo, "PAT_TOKEN", cfg.BakGithubToken)
	}
	return nil
}
func addRepoSecret(ctx context.Context, client *github.Client, owner string, repo, secretName string, secretValue string) error {
	publicKey, _, err := client.Actions.GetRepoPublicKey(ctx, owner, repo)
	if err != nil {
		return err
	}

	encryptedSecret, err := encryptSecretWithPublicKey(publicKey, secretName, secretValue)
	if err != nil {
		return err
	}

	if _, err := client.Actions.CreateOrUpdateRepoSecret(ctx, owner, repo, encryptedSecret); err != nil {
		return fmt.Errorf("Actions.CreateOrUpdateRepoSecret returned error: %v", err)
	}

	return nil
}

func encryptSecretWithPublicKey(publicKey *github.PublicKey, secretName string, secretValue string) (*github.EncryptedSecret, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey.GetKey())
	if err != nil {
		return nil, fmt.Errorf("base64.StdEncoding.DecodeString was unable to decode public key: %v", err)
	}

	var boxKey [32]byte
	copy(boxKey[:], decodedPublicKey)
	encryptedBytes, err := box.SealAnonymous([]byte{}, []byte(secretValue), &boxKey, crypto_rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("box.SealAnonymous failed with error %w", err)
	}

	encryptedString := base64.StdEncoding.EncodeToString(encryptedBytes)
	keyID := publicKey.GetKeyID()
	encryptedSecret := &github.EncryptedSecret{
		Name:           secretName,
		KeyID:          keyID,
		EncryptedValue: encryptedString,
	}
	return encryptedSecret, nil
}
func AddOrUpdateFile(client *github.Client, ctx context.Context, branch, filePath string, fileContent []byte) error {
	newFile := false
	fc, _, _, err := client.Repositories.GetContents(ctx, cfg.BakRepoOwner, cfg.BakRepo, filePath, &github.RepositoryContentGetOptions{Ref: branch})
	if err != nil {
		responseErr, ok := err.(*github.ErrorResponse)
		if !ok || responseErr.Response.StatusCode != 404 {
			newFile = false
		} else {
			newFile = true
		}
	}
	currentSHA := ""
	commitMessage := fmt.Sprintf("Add file: %s", filePath)
	if !newFile {
		currentSHA = *fc.SHA
		commitMessage = fmt.Sprintf("Update file: %s", filePath)
		_, _, err = client.Repositories.UpdateFile(ctx, cfg.BakRepoOwner, cfg.BakRepo, filePath, &github.RepositoryContentFileOptions{
			Message: &commitMessage,
			SHA:     &currentSHA,
			Content: fileContent,
			Branch:  &branch,
		})
	} else {
		_, _, err = client.Repositories.CreateFile(ctx, cfg.BakRepoOwner, cfg.BakRepo, filePath, &github.RepositoryContentFileOptions{
			Message: &commitMessage,
			Content: fileContent,
			Branch:  &branch,
		})
	}
	if err != nil {
		log.Println(err)
	}
	return err
}

func DownloadFile(downUrl, filePath string) {

	tr := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	}}
	if cfg.BakProxy != "" {
		proxyUrl, err := url.Parse(cfg.BakProxy)
		if err == nil {
			tr.Proxy = http.ProxyURL(proxyUrl)
		}
	}

	// 创建一个带有自定义 Transport 的 Client
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, downUrl, nil)
	if err != nil {
		log.Fatal(err)
	}
	r, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if r != nil {
		defer r.Body.Close()
	}

	// 获得get请求响应的reader对象
	reader := bufio.NewReaderSize(r.Body, 32*1024)
	file, err := os.Create(filePath)
	defer file.Close()
	if err != nil {
		panic(err)
	}
	// 获得文件的writer对象
	writer := bufio.NewWriter(file)

	io.Copy(writer, reader)
}

// 打包成zip文件
func Zip(src_dir string, zip_file_name string) {
	// 预防：旧文件无法覆盖
	os.RemoveAll(zip_file_name)

	// 创建：zip文件
	zipfile, _ := os.Create(zip_file_name)
	defer zipfile.Close()

	// 打开：zip文件
	archive := zip.NewWriter(zipfile)
	defer archive.Close()

	// 遍历路径信息
	filepath.Walk(src_dir, func(path string, info os.FileInfo, _ error) error {
		// 如果是源路径，提前进行下一个遍历
		if path == src_dir {
			return nil
		}

		// 获取：文件头信息
		header, _ := zip.FileInfoHeader(info)
		relPath, _ := filepath.Rel(src_dir, path)
		header.Name = filepath.ToSlash(relPath)

		// 判断：文件是不是文件夹
		if info.IsDir() {
			header.Name += "/"
		} else {
			// 设置：zip的文件压缩算法
			header.Method = zip.Deflate
		}

		// 创建：压缩包头部信息
		writer, _ := archive.CreateHeader(header)
		if !info.IsDir() {
			file, _ := os.Open(path)
			defer file.Close()
			io.Copy(writer, file)
		}
		return nil
	})
}

func Unzip(zipPath, dstDir string) error {
	// open zip file
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, file := range reader.File {
		if err := unzipFile(file, dstDir); err != nil {
			return err
		}
	}
	return nil
}

func unzipFile(file *zip.File, dstDir string) error {
	// create the directory of file
	filePath := path.Join(dstDir, file.Name)
	if file.FileInfo().IsDir() {
		if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return err
	}

	// open the file
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	// create the file
	w, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer w.Close()

	// save the decompressed file content
	_, err = io.Copy(w, rc)
	return err
}

type TableData struct {
	Headers []string
	Rows    [][]string
}

type ReadmeData struct {
	Title      string
	LastUpdate string
	Table      TableData
}

func chineseTimeStr(t time.Time, layout string) string {
	loc := time.FixedZone("UTC+8", 8*60*60)
	currentTime := t.In(loc)
	formattedTime := currentTime.Format(layout)
	return formattedTime
}
